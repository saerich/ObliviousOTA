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



void BlindDownloadFirmware(const char* downloadServerURL, const char* deviceFirmwareKey, const char* username, const uint8_t skClient[OPAQUE_SHARED_SECRETBYTES])
{
    uint8_t deviceKey[crypto_core_ristretto255_BYTES];
    URLDecodeHexString(deviceFirmwareKey, deviceKey);

    ESP_LOGI("DeviceKey", "Original Device Key %s", deviceFirmwareKey);
    ESP_LOG_BUFFER_HEX("DeviceKey", deviceKey, sizeof(deviceKey));
    
    //Okay, first off, we need to create an identifier for the specific file; we know the firmware key, and the server knows ALL the firmware keys.
    crypto_hash_sha512_state st;
    uint8_t fwHash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_init(&st);
    static const char* firmwareDomain = "fw";
    crypto_hash_sha512_update(&st, (const uint8_t*)firmwareDomain, (uint16_t)strlen(firmwareDomain));
    crypto_hash_sha512_update(&st, skClient, OPAQUE_SHARED_SECRETBYTES); // Since the shared key is known by both the server and client, it's safe to use.
    crypto_hash_sha512_update(&st, (const uint8_t*)deviceKey, crypto_core_ristretto255_BYTES); //Firmware key.
    crypto_hash_sha512_final(&st, fwHash);

    ESP_LOG_BUFFER_HEX("Hash", fwHash, sizeof(fwHash));

    //Now, we have a unique per-session, unique per-firmware "code" that the server can construct too in the bundle, we need the header from the server, and we can retrieve beta[key] too.
    //It doesn't matter if the server knows who downloaded *something*, as long as the device does not leak WHAT they downloaded?
    //This doesn't leak any keys, because this is just the "identity" value for the block.

    char* url = malloc(1024);;
    char fwHashString[sizeof(fwHash)*2+1];
    URLEncodeByteArray(fwHash, sizeof(fwHash), fwHashString, sizeof(fwHashString));

    uint8_t r[32];
    uint8_t r2[32];
    uint8_t alpha[32];
    uint8_t alpha2[32];

    oprf_Blind((const uint8_t*)deviceKey, crypto_core_ristretto255_BYTES, r, alpha); //Still not providing deviceFirmwareKey to the server
    oprf_Blind((const uint8_t*)fwHash, crypto_hash_sha512_BYTES, r2, alpha2);

    char alphaString[32*2+1];
    URLEncodeByteArray(alpha, 32, alphaString, sizeof(alphaString));
    char alpha2String[32*2+1];
    URLEncodeByteArray(alpha2, 32, alpha2String, sizeof(alpha2String));
    snprintf(url, 1024, "/Download?Username=%s&Alpha1=%s&Alpha2=%s", username, alphaString, alpha2String); //This could be in post to avoid needing to leak alpha or username in URL, Could probably also blind username with an alpha/flow earlier.

    //Now, we need to read the server response sensibly, header first, select the firmware, write choice to the correct ota provision.
    ESP_LOGI("Download", "Attempting to download from %s", url); 

    const char* pUrl = downloadServerURL;
    if(strncmp(downloadServerURL, "http://", 7) == 0) { pUrl += 7;}
    else if(strncmp(downloadServerURL, "https://", 8) == 0) { pUrl += 8; }

    ESP_LOGI("Download", "URL: %s", pUrl);

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

    char req[512];
    int n = snprintf(req, sizeof(req), 
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "Accept: application/octet-stream\r\n"
        "\r\n",
        url, pUrl
    );

    free(url);

    if(n <= 0 || n > (int)sizeof(req))
    {
        ESP_LOGE("HTTP", "Request too large.");
        close(sock);
        return;
    }
    if(send(sock, req, n, 0) != n) 
    {
        ESP_LOGE("HTTP", "Send failed. Errno=%d, (%s)", errno, strerror(errno));
        close(sock);
        return;
    }

    if(!socketBypassHttpHeaders(sock))
    {
        ESP_LOGE("HTTP", "Failed to skip HTTP Headers.");
        close(sock);
        return;
    }

    uint8_t beta[32];
    uint8_t N[32];
    uint8_t rwdU[64];
    uint8_t rwdU2[64];


    socketReadExact(sock, beta, 32);
    ESP_LOG_BUFFER_HEX("R", r, 32);

    if(oprf_Unblind(r, beta, N) != 0)
    {
        ESP_LOGE("OPRF", "Could not calculate N");
    }
    ESP_LOG_BUFFER_HEX("beta", beta, 32);
    
    if(oprf_Finalize(deviceKey, crypto_core_ristretto255_BYTES, N, rwdU) != 0) 
    {
        ESP_LOGE("OPRF", "Could not finalize N");
        close(sock);
        return;
    }
    
    socketReadExact(sock, beta, 32); //2nd Beta.
    oprf_Unblind(r2, beta, N);
    oprf_Finalize(fwHash, crypto_hash_sha512_BYTES, N, rwdU2);

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
            ESP_LOGI("Slot", "Found slot.");
            uint8_t slotAeadKey[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
            crypto_generichash_state slotSt;
            static const char* firmwareSzDomain = "firmwareSize";
            crypto_generichash_init(&slotSt, NULL, 0, 32);
            crypto_generichash_update(&slotSt, (const uint8_t*) firmwareSzDomain, strlen(firmwareSzDomain));
            crypto_generichash_update(&slotSt, rwdU2, 64);
            crypto_generichash_update(&slotSt, fwHash, 64);
            crypto_generichash_update(&slotSt, skClient, OPAQUE_SHARED_SECRETBYTES);
            crypto_generichash_final(&slotSt, slotAeadKey, 32);
            unsigned long long sizeRawLength = 0;
            uint8_t tmpActualSize[8];
            if(crypto_aead_chacha20poly1305_ietf_decrypt(tmpActualSize, &sizeRawLength, NULL, sizeCrypt, sizeof(sizeCrypt), NULL, 0, sizeNonce, slotAeadKey) != 0)
            {
                ESP_LOGE("Firmware", "Could not get actual firmware size.");
                return;
            }

            actualSize |= ((uint64_t)tmpActualSize[0] << 0);
            actualSize |= ((uint64_t)tmpActualSize[1] << 8);
            actualSize |= ((uint64_t)tmpActualSize[2] << 16);
            actualSize |= ((uint64_t)tmpActualSize[3] << 24);
            actualSize |= ((uint64_t)tmpActualSize[4] << 32);
            actualSize |= ((uint64_t)tmpActualSize[5] << 40);
            actualSize |= ((uint64_t)tmpActualSize[6] << 48);
            actualSize |= ((uint64_t)tmpActualSize[7] << 56);
        }

    }
    if(slotNumber == -1) { ESP_ERROR_CHECK(ESP_ERR_HW_CRYPTO_BASE); }

    int expectedBlocks = 4096;
    int skipBlocks = slotNumber * expectedBlocks; //4096 = 4mb firmware image / 1024 byte block sizes.
    socketSkipNBlocks(sock, skipBlocks, 1052);

    ESP_LOGI("Download", "Skipped %d blocks", skipBlocks);
    
    uint8_t aeadKey[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    crypto_generichash_state gSt;
    static const char* firmwareFileDomain = "firmwareFile";
    crypto_generichash_init(&gSt, NULL, 0, sizeof(aeadKey));
    crypto_generichash_update(&gSt, (const uint8_t*) firmwareFileDomain, strlen(firmwareFileDomain));
    crypto_generichash_update(&gSt, rwdU, 64);
    crypto_generichash_update(&gSt, deviceKey, crypto_core_ristretto255_BYTES);
    crypto_generichash_update(&gSt, skClient, OPAQUE_SHARED_SECRETBYTES);
    crypto_generichash_final(&gSt, aeadKey, sizeof(aeadKey));
    
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

        if(crypto_aead_chacha20poly1305_ietf_decrypt(raw, &rawLen, NULL, cipherText, sizeof(cipherText), NULL, 0, nonce, aeadKey) != 0)
        {
            ESP_LOGE("DECRYPT", "Decryption failed, for some reason.");
            ESP_LOG_BUFFER_HEX("DECRYPT", nonce, sizeof(nonce));
            close(sock);
            return;
            ESP_ERROR_CHECK(ESP_ERR_INVALID_RESPONSE);
        }

        size_t effectiveLength = (remaining < sizeof(raw) ? (size_t)remaining : sizeof(1024));
        esp_ota_write(otaHandle, raw, effectiveLength);
        
        remaining -= effectiveLength;
        if(remaining <= 0)
        {
            sodium_memzero(aeadKey, sizeof(aeadKey));
            sodium_memzero(rwdU, sizeof(rwdU));
            sodium_memzero(rwdU2, sizeof(rwdU2));
            esp_app_desc_t appDesc;
            esp_err_t err = esp_ota_get_partition_description(nextPartition, &appDesc);
            ESP_ERROR_CHECK_WITHOUT_ABORT(err);
            if(err != ESP_OK)
            {
                esp_partition_erase_range(nextPartition, 0, nextPartition->size);
            }
            esp_ota_end(otaHandle);
            close(sock);
            return;
        }
    }
    close(sock);




}