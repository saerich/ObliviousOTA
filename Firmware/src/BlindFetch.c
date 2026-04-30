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
#include <esp_http_client.h>

#ifdef PlainOTA
#include <esp_https_ota.h>
#include <esp_timer.h>
#endif

#ifdef PlainOTA
uint64_t PlainOTADownload(const char* downloadURL)
{
    char url[256];
    snprintf(url, sizeof(url), "%s%s", downloadURL, "/PlainOTA");

    esp_http_client_config_t config = 
    {
        .url = url,
        .method = HTTP_METHOD_POST,
        .cert_pem = (char *)pemStart,
    };
    esp_https_ota_config_t ota_config = 
    {
        .http_config = &config,
    };
    esp_err_t ret = esp_https_ota(&ota_config);
    if (ret == ESP_OK) 
    {
        uint64_t endTime = esp_timer_get_time();
        const esp_partition_t *after = esp_ota_get_boot_partition();
        const esp_partition_t *running = esp_ota_get_running_partition();
        esp_ota_set_boot_partition(running);
        esp_partition_erase_range(after, 0, after->size);
        return endTime;
    } 
    return ESP_FAIL;
}
#endif

void OTAHeaderGeneration(const char* downloadServerURL, const char* deviceFirmwareKey, const char* username, const uint8_t skClient[OPAQUE_SHARED_SECRETBYTES])
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
    
    size_t bodyLen = sizeof(alpha) + sizeof(alpha2) + sizeof(uint32_t) + strlen(username);
    uint8_t* body = malloc(bodyLen);
    if(!body)
    { 
        ESP_LOGE("HTTP", "Could not allocate body");
        return; 
    }
    uint8_t* p = body;
    
    memcpy(p, alpha, sizeof(alpha));
    p += sizeof(alpha);

    memcpy(p, alpha2, sizeof(alpha2));
    p += sizeof(alpha2);
    
    uint32_t unameLen = strlen(username);
    memcpy(p, &unameLen, sizeof(unameLen));
    p += sizeof(unameLen);
    
    memcpy(p, username, strlen(username));

    int statusCode = 0;
    esp_http_client_handle_t c;
    ESP_ERROR_CHECK(TLSPost(downloadServerURL, "/GenerateHeaders", body, bodyLen, &c, &statusCode));
    HttpFree(&c);

    free(body);
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
    
    size_t bodyLen = sizeof(alpha) + sizeof(alpha2) + sizeof(uint32_t) + strlen(username);
    uint8_t* body = malloc(bodyLen);
    if(!body)
    { 
        ESP_LOGE("HTTP", "Could not allocate body");
        return; 
    }
    uint8_t* p = body;
    
    memcpy(p, alpha, sizeof(alpha));
    p += sizeof(alpha);

    memcpy(p, alpha2, sizeof(alpha2));
    p += sizeof(alpha2);
    
    uint32_t unameLen = strlen(username);
    memcpy(p, &unameLen, sizeof(unameLen));
    p += sizeof(unameLen);
    
    memcpy(p, username, strlen(username));

    int statusCode = 0;
    esp_http_client_handle_t c;
    ESP_ERROR_CHECK(TLSPost(downloadServerURL, "/Download", body, bodyLen, &c, &statusCode));

    free(body);

    uint8_t beta[32];
    uint8_t beta2[32];
    uint8_t N[32];
    uint8_t N2[32];
    uint8_t rwdU[64];
    uint8_t rwdU2[64];
    ResponseReadUpTo(c, beta, 32);

    if(oprf_Unblind(r, beta, N) != 0)
    {
        ESP_LOGE("OPRF", "Could not calculate N");
        HttpDrainAndFree(&c);
        return;
    }
    
    if(oprf_Finalize(deviceKey, crypto_core_ristretto255_BYTES, N, rwdU) != 0) 
    {
        ESP_LOGE("OPRF", "Could not finalize N");
        HttpDrainAndFree(&c);
        return;
    }
    
    ResponseReadUpTo(c, beta2, 32);
    if(oprf_Unblind(r2, beta2, N2) != 0)
    {
        ESP_LOGE("OPRF", "Could not calculate N2");
        HttpDrainAndFree(&c);
        return;
    }
    if(oprf_Finalize(fwHash, crypto_hash_sha512_BYTES, N2, rwdU2) != 0)
    {
        ESP_LOGE("OPRF", "Could not finalize N2");
        HttpDrainAndFree(&c);
        return;
    }

    uint8_t numberOfSKUs[4];
    ResponseReadUpTo(c, numberOfSKUs, sizeof(numberOfSKUs));

    uint32_t numberSKUs = 0;
    numberSKUs = ((uint32_t)numberOfSKUs[0]) | ((uint32_t)numberOfSKUs[1] << 8) | ((uint32_t)numberOfSKUs[2] << 16) | ((uint32_t) numberOfSKUs[3] << 24);
    
    int slotNumber = -1;
    uint64_t actualSize = 0;
    for(int i = 0; i < numberSKUs; i++)
    {
        uint8_t sizeNonce[12];
        uint8_t sizeCrypt[24];
        ResponseReadUpTo(c, sizeNonce, sizeof(sizeNonce));
        ResponseReadUpTo(c, sizeCrypt, sizeof(sizeCrypt));

        uint8_t slotAeadKey[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
        CalculateFirmwareSizeKey(rwdU2, fwHash, skClient, slotAeadKey);
        unsigned long long sizeRawLength = 0;
        uint8_t tmpActualSize[8];
        if(crypto_aead_chacha20poly1305_ietf_decrypt(tmpActualSize, &sizeRawLength, NULL, sizeCrypt, sizeof(sizeCrypt), NULL, 0, sizeNonce, slotAeadKey) == 0)
        {
            slotNumber = i;
            ESP_LOGI("Slot", "Found slot %d.", slotNumber);
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

    int discardBlocks = slotNumber * expectedBlocks; //4096 = 4mb firmware image / 1024 byte block sizes.
    //Effectively we want to read and discard n bytes, in blocks, each block is 1052 bytes,  slot number * expectedBlocks * 1052 = total bytes to read and discard.
    ResponseDiscard(c, discardBlocks * 1052);

    ESP_LOGI("Download", "Discarded %d blocks", discardBlocks);
    
    uint8_t aeadKey[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    CalculateFirmwareFileKey(rwdU, deviceKey, skClient, aeadKey);
    ESP_LOGI("Encryption", "Calculated Device firmware file key");
    
    esp_ota_handle_t otaHandle;
    const esp_partition_t* nextPartition = esp_ota_get_next_update_partition(NULL);
    esp_ota_begin(nextPartition, actualSize, &otaHandle);

    ESP_LOGI("OTA", "Selected next OTA partition");

    long remaining = actualSize;
    for(int i = 0; i < expectedBlocks; i++)
    {
        uint8_t nonce[12];
        uint8_t cipherText[1040];
        uint8_t raw[1024];

        unsigned long long rawLen;

        ResponseReadUpTo(c, nonce, 12);
        ESP_LOGI("Encryption", "Received raw nonce");
        ResponseReadUpTo(c, cipherText, 1040);
        ESP_LOGI("Encryption", "Retrieved ciphertext.");

        uint8_t nonceKey[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
        CalculateNonceKey(nonce, rwdU, (const uint8_t*)&i, nonceKey);
        ESP_LOGI("Encryption", "Calculated nonce key");

        uint8_t aad[72];
        CreateAAD((const uint8_t*)&slotNumber, (const uint8_t*)&i, rwdU, aad);
        ESP_LOGI("Encryption", "Calculated AAD");

        if(crypto_aead_chacha20poly1305_ietf_decrypt(raw, &rawLen, NULL, cipherText, sizeof(cipherText), aad, sizeof(aad), nonceKey, aeadKey) != 0)
        {
            ESP_LOGE("DECRYPT", "Decryption failed, for some reason.");
            HttpDrainAndFree(&c);
            esp_partition_erase_range(nextPartition, 0, nextPartition->size);
            esp_ota_end(otaHandle);
            return;
        }

        size_t effectiveLength = (remaining < sizeof(raw) ? (size_t)remaining : sizeof(raw));
        esp_ota_write(otaHandle, raw, effectiveLength);
        
        remaining -= effectiveLength;
        if(remaining <= 0)
        {
            #ifndef EarlyClose
                int discarded = 0;
                esp_http_client_flush_response(c, &discarded); //No point in manually flushing, this does it for us.
                ESP_LOGI("HTTP", "Discarded %d bytes", discarded);
                HttpFree(&c);
            #else
                HttpFree(&c);
            #endif
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
                return;
            }
            #ifndef APPLY_FIRMWARE
            esp_partition_erase_range(nextPartition, 0, nextPartition->size);
            esp_ota_end(otaHandle);
            #else
            esp_ota_end(otaHandle);
            esp_ota_set_boot_partition(nextPartition);
            esp_restart();
            #endif

            return;
        }
    }

    
    HttpFree(&c);
}