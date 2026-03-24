#include "BlindFetch.h"
#include <HTTP.h>
#include <sodium.h>
#include <string.h>
#include <esp_log.h>
#include <oprf/oprf.h>
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include <errno.h>
#include <esp_ota_ops.h>
#include "../../Interop/Interop.h"

static bool socketBypassHttpHeaders(int sock)
{
    char c;
    char last4[4] = {0};

    while (1) 
    {
        int r = recv(sock, &c, 1, 0);
        if (r <= 0) { return false; }

        last4[0] = last4[1];
        last4[1] = last4[2];
        last4[2] = last4[3];
        last4[3] = c;

        if (memcmp(last4, "\r\n\r\n", 4) == 0) { return true; }
    }
}

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

static void socketSkipNBlocks(int sock, int n, int size)
{
    int remaining = n*size;
    uint8_t* c = malloc(size);

    while (remaining != 0) 
    {
        int r = recv(sock, c, MIN(size, remaining), 0);
        remaining -= r;
    }
    free(c);
}


static bool socketReadExact(int sock, uint8_t *buf, size_t len)
{
    size_t got = 0;
    while (got < len) 
    {
        int r = recv(sock, buf + got, len - got, 0);
        if (r <= 0) { return false; } // 0=EOF, <0=error
        got += (size_t)r;
    }
    return true;
}

bool splitHostAndPort(const char *in, char *host, size_t hostSize, char *port, size_t portSize)
{
    const char *colon = strrchr(in, ':');
    if (!colon) return false;

    size_t host_len = colon - in;
    size_t port_len = strlen(colon + 1);

    if (host_len == 0 || host_len >= hostSize){ return false; }
    if (port_len == 0 || port_len >= portSize){ return false; }

    memcpy(host, in, host_len);
    host[host_len] = '\0';

    memcpy(port, colon + 1, port_len);
    port[port_len] = '\0';

    return true;
}

static bool socketSendAll(int sock, const void* data, size_t dataLen)
{
    const uint8_t* p = (const uint8_t*) data;
    while(dataLen > 0)
    {
        int res = send(sock, p, dataLen, 0);
        if(res < 0) { if(errno == EINTR) { continue; } return false; }
        if(res == 0) { return false; }
        p += (size_t) res;
        dataLen -= (size_t) res;
    }
    return true;
}

void BlindDownloadFirmware(const char* downloadServerURL, const char* deviceFirmwareKey, const char* username, const uint8_t skClient[OPAQUE_SHARED_SECRETBYTES])
{
    uint8_t deviceKey[crypto_core_ristretto255_BYTES];
    URLDecodeHexString(deviceFirmwareKey, deviceKey);

    //Okay, first off, we need to create an identifier for the specific file; we know the firmware key, and the server knows ALL the firmware keys.
    uint8_t fwHash[crypto_hash_sha512_BYTES];
    CreateKeyFromSKUKey(skClient, deviceKey, fwHash);

    uint8_t r[32];
    uint8_t r2[32];
    uint8_t alpha[32];
    uint8_t alpha2[32];

    oprf_Blind((const uint8_t*)deviceKey, crypto_core_ristretto255_BYTES, r, alpha); //Still not providing deviceFirmwareKey to the server
    oprf_Blind((const uint8_t*)fwHash, crypto_hash_sha512_BYTES, r2, alpha2);

    const char* pUrl = downloadServerURL;
    if(strncmp(downloadServerURL, "http://", 7) == 0) { pUrl += 7;}
    else if(strncmp(downloadServerURL, "https://", 8) == 0) { pUrl += 8; }

    struct addrinfo hints = 
    {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM
    };
    struct addrinfo* res = NULL;

    char* host = malloc(64);
    char port[6];

    if(!splitHostAndPort(pUrl, host, 64, port, sizeof(port))) 
    {
        ESP_LOGE("HTTP", "Couldn't split host and port.");
        return;
    }

    int err = getaddrinfo(host, port, &hints, &res);
    if(err != 0 || !res) { ESP_LOGE("HTTP", "Could not getaddrinfo. %d", err); return; }
    free(host);

    int sock = socket(res->ai_family, res->ai_socktype, 0);
    if(sock < 0)
    {
        ESP_LOGE("HTTP", "Socket failed to open.");
        freeaddrinfo(res);
        return;
    }

    if(connect(sock, res->ai_addr, res->ai_addrlen) != 0)
    {
        ESP_LOGE("HTTP", "Failed to connect.");
        close(sock);
        freeaddrinfo(res);
        return;
    }
    size_t bodyLen = sizeof(alpha) + sizeof(alpha2) + strlen(username);
    char req[512];
    int n = snprintf(req, sizeof(req), 
        "POST /Download HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "Accept: application/octet-stream\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %zu\r\n"
        "\r\n",
        pUrl, bodyLen
    );

    uint8_t* body = malloc(bodyLen);
    if(!body)
    { 
        ESP_LOGE("HTTP", "Could not allocate body");
        close(sock);
        return; 
    }

    memcpy(body, alpha, sizeof(alpha));
    memcpy(body + sizeof(alpha), alpha2, sizeof(alpha2));
    memcpy(body + sizeof(alpha) + sizeof(alpha2), username, strlen(username));

    if(n <= 0 || n > (int)sizeof(req))
    {
        ESP_LOGE("HTTP", "Request too large.");
        free(body);
        close(sock);
        return;
    }
    if(!socketSendAll(sock, req, n)) 
    {
        ESP_LOGE("HTTP", "Send failed. Errno=%d, (%s)", errno, strerror(errno));
        free(body);
        close(sock);
        return;
    }
    if(!socketSendAll(sock, body, bodyLen))
    {
        ESP_LOGE("HTTP", "Could not send data packets to server.");
        free(body);
        close(sock);
        return;
    }

    free(body);

    if(!socketBypassHttpHeaders(sock))
    {
        ESP_LOGE("HTTP", "Failed to skip HTTP Headers.");
        close(sock);
        return;
    }

    uint8_t beta[32];
    uint8_t beta2[32];
    uint8_t N[32];
    uint8_t N2[32];
    uint8_t rwdU[64];
    uint8_t rwdU2[64];

    socketReadExact(sock, beta, 32);

    if(oprf_Unblind(r, beta, N) != 0)
    {
        ESP_LOGE("OPRF", "Could not calculate N");
    }
    
    if(oprf_Finalize(deviceKey, crypto_core_ristretto255_BYTES, N, rwdU) != 0) 
    {
        ESP_LOGE("OPRF", "Could not finalize N");
        close(sock);
        return;
    }
    
    socketReadExact(sock, beta2, 32); //2nd Beta.
    oprf_Unblind(r2, beta2, N2);
    oprf_Finalize(fwHash, crypto_hash_sha512_BYTES, N2, rwdU2);

    uint8_t numberOfSKUs[4];
    socketReadExact(sock, numberOfSKUs, sizeof(numberOfSKUs));
    uint32_t numberSKUs = 0;
    numberSKUs = ((uint32_t)numberOfSKUs[0]) | ((uint32_t)numberOfSKUs[1] << 8) | ((uint32_t)numberOfSKUs[2] << 16) | ((uint32_t) numberOfSKUs[3] << 24);
    
    int slotNumber = -1;
    uint64_t actualSize = 0;
    for(int i = 0; i < numberSKUs; i++)
    {
        uint8_t foundHash[crypto_hash_sha512_BYTES];
        socketReadExact(sock, foundHash, sizeof(foundHash));
        uint8_t sizeNonce[12];
        uint8_t sizeCrypt[24];
        socketReadExact(sock, sizeNonce, sizeof(sizeNonce));
        socketReadExact(sock, sizeCrypt, sizeof(sizeCrypt));

        if(memcmp(foundHash, fwHash, sizeof(fwHash)) == 0) 
        { 
            slotNumber = i; 
            ESP_LOGI("Slot", "Found slot %d.", slotNumber);
            uint8_t slotAeadKey[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
            CalculateFirmwareSizeKey(rwdU2, fwHash, skClient, slotAeadKey);

            unsigned long long sizeRawLength = 0;
            uint8_t tmpActualSize[8];
            if(crypto_aead_chacha20poly1305_ietf_decrypt(tmpActualSize, &sizeRawLength, NULL, sizeCrypt, sizeof(sizeCrypt), NULL, 0, sizeNonce, slotAeadKey) != 0)
            {
                ESP_LOGE("Firmware", "Could not get actual firmware size.");
                return;
            }

            actualSize = ((uint64_t)tmpActualSize[0] << 0) |
                ((uint64_t)tmpActualSize[1] << 8) |
                ((uint64_t)tmpActualSize[2] << 16) |
                ((uint64_t)tmpActualSize[3] << 24) |
                ((uint64_t)tmpActualSize[4] << 32) |
                ((uint64_t)tmpActualSize[5] << 40) |
                ((uint64_t)tmpActualSize[6] << 48) |
                ((uint64_t)tmpActualSize[7] << 56);
        }

    }
    if(slotNumber == -1) { ESP_ERROR_CHECK(ESP_ERR_HW_CRYPTO_BASE); }

    int expectedBlocks = 4096;
    int skipBlocks = slotNumber * expectedBlocks; //4096 = 4mb firmware image / 1024 byte block sizes.
    socketSkipNBlocks(sock, skipBlocks, 1052);

    ESP_LOGI("Download", "Skipped %d blocks", skipBlocks);
    
    uint8_t aeadKey[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    CalculateFirmwareFileKey(rwdU, deviceKey, skClient, aeadKey);
    
    esp_ota_handle_t otaHandle;
    const esp_partition_t* nextPartition = esp_ota_get_next_update_partition(NULL);
    esp_ota_begin(nextPartition, actualSize, &otaHandle);

    size_t remaining = actualSize;
    for(int i = 0; i < expectedBlocks; i++)
    {
        uint8_t nonce[12];
        uint8_t cipherText[1040];
        uint8_t raw[1024];

        unsigned long long rawLen;

        socketReadExact(sock, nonce, 12);
        socketReadExact(sock, cipherText, 1040);

        uint8_t nonceKey[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
        CalculateNonceKey(nonce, rwdU, (const uint8_t*)i, nonceKey);

        uint8_t aad[72];
        CreateAAD((const uint8_t*)slotNumber, (const uint8_t*)i, rwdU, aad);

        if(crypto_aead_chacha20poly1305_ietf_decrypt(raw, &rawLen, NULL, cipherText, sizeof(cipherText), aad, sizeof(aad), nonceKey, aeadKey) != 0)
        {
            ESP_LOGE("DECRYPT", "Decryption failed, for some reason.");
            close(sock);
            return;
            ESP_ERROR_CHECK(ESP_ERR_INVALID_RESPONSE);
        }

        size_t effectiveLength = (remaining < sizeof(raw) ? (size_t)remaining : sizeof(raw));
        esp_ota_write(otaHandle, raw, effectiveLength);
        
        remaining -= effectiveLength;
        if(remaining <= 0)
        {
            //Skip remaining blocks in present stream:
            if(expectedBlocks - i > 0) { socketSkipNBlocks(sock, expectedBlocks - i, 1052); }
            //if not in the last block:
            if(numberSKUs - slotNumber > 0) { socketSkipNBlocks(sock, numberSKUs-slotNumber, 1052); }

            //Send R, Alpha, Beta, N, RWDU to server, only if KTVs are enabled.
            #ifdef SEND_KTVS
                char* url = malloc(2048);
                char fwHashString[sizeof(fwHash)*2+1];
                URLEncodeByteArray(fwHash, sizeof(fwHash), fwHashString, sizeof(fwHashString));
                
                char alphaString[32*2+1];
                URLEncodeByteArray(alpha, 32, alphaString, sizeof(alphaString));
                char alpha2String[32*2+1];
                URLEncodeByteArray(alpha2, 32, alpha2String, sizeof(alpha2String));
                char betaString[32*2+1];
                URLEncodeByteArray(beta, 32, betaString, sizeof(betaString));
                char beta2String[32*2+1];
                URLEncodeByteArray(beta2, 32, beta2String, sizeof(beta2String));
                char nString[32*2+1];
                URLEncodeByteArray(N, 32, nString, sizeof(nString));
                char n2String[32*2+1];
                URLEncodeByteArray(N2, 32, n2String, sizeof(n2String));
                char rwdString[64*2+1];
                URLEncodeByteArray(rwdU, 64, rwdString, sizeof(rwdString));
                char rwd2String[64*2+1];
                URLEncodeByteArray(rwdU2, 64, rwd2String, sizeof(rwd2String));
                char skStr[64*2+1];
                URLEncodeByteArray(skClient, 64, skStr, sizeof(skStr));
                snprintf(url, 2048, "%s/KTV?Username=%s&Alpha1=%s&Alpha2=%s&Beta1=%s&Beta2=%s&N1=%s&N2=%s&rwdU1=%s&rwdU2=%s&deviceKey=%s&fwHash=%s&realBlocks=%llu&absorbedBlocks=%u&sk=%s", 
                    downloadServerURL, username, alphaString, alpha2String, betaString, beta2String, nString, n2String, rwdString, rwd2String, deviceFirmwareKey, fwHashString, actualSize, i+1, skStr); 
                int statusCode = 0;
                HTTPGet(url, &statusCode);
                ESP_LOGI("KTV", "KTVs Sent to server, status code was %d", statusCode);
            #endif

            sodium_memzero(aeadKey, sizeof(aeadKey));
            sodium_memzero(rwdU, sizeof(rwdU));
            sodium_memzero(rwdU2, sizeof(rwdU2));
            esp_app_desc_t appDesc;
            esp_err_t err = esp_ota_get_partition_description(nextPartition, &appDesc);
            ESP_ERROR_CHECK_WITHOUT_ABORT(err);
            if(err != ESP_OK)
            {
                esp_partition_erase_range(nextPartition, 0, nextPartition->size);
                esp_ota_end(otaHandle);
                close(sock);
                return;
            }
            close(sock);
            esp_ota_end(otaHandle);
            esp_ota_set_boot_partition(nextPartition);
            esp_restart();
            return;
        }
    }
    close(sock);
}