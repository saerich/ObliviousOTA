#include "NetworkedOPAQUE.h"
#include <esp_err.h>
#include <stdbool.h>
#include <esp_log.h>
#include <HTTP.h>

esp_err_t NetworkedOPAQUERegister(const char* opaqueServerUrl, const char* username, const char* password)
{
    uint8_t alpha[crypto_core_ristretto255_BYTES];
    uint8_t* cSec = NULL;
    uint16_t cPasswordLen;
    OPAQUEClientRegister(password, alpha, &cSec, &cPasswordLen);

    char encodedAlpha[sizeof(alpha)*2+1];
    URLEncodeByteArray(alpha, sizeof(alpha), encodedAlpha, sizeof(encodedAlpha));

    char url[1024];
    snprintf(url, sizeof(url), "%s/Register?Alpha=%s&Username=%s", opaqueServerUrl, encodedAlpha, username);
    int statusCode = 0;
    cJSON* registerResponse = HTTPGetJSON(url, &statusCode);
    const char* rPubStr = cJSON_GetStringValue(registerResponse);

    //Send alpha to Server, then Finalize Register
    uint8_t rPub[OPAQUE_REGISTER_PUBLIC_LEN];
    for(size_t i = 0; i < strlen(rPubStr)/2; i++) { sscanf(rPubStr + (i*2), "%2hhx", &rPub[i]); }
    cJSON_Delete(registerResponse);

    uint8_t regRec[OPAQUE_REGISTRATION_RECORD_LEN];
    uint8_t exportKeyReg[crypto_hash_sha512_BYTES];

    OPAQUEClientFinalizeRegister(rPub, cSec, cPasswordLen, regRec, exportKeyReg);

    char encodedRegRec[sizeof(regRec)*2+1];
    URLEncodeByteArray(regRec, sizeof(regRec), encodedRegRec, sizeof(encodedRegRec));
    
    memset(url, 0x00, sizeof(url));
    snprintf(url, sizeof(url), "%s/RegisterFinalize?RegisterRecord=%s&Username=%s", opaqueServerUrl, encodedRegRec, username);
    HTTPGetJSON(url, &statusCode);

    return ESP_OK;
}

esp_err_t NetworkedOPAQUELogin(const char* password)
{
    ClientState_t cState = {0};
    uint8_t ke1[OPAQUE_USER_SESSION_PUBLIC_LEN];
    OPAQUEClientLogin(password, &cState, ke1);
    //send ke1 to server; get ke2 back?
    uint8_t ke2[OPAQUE_SERVER_SESSION_LEN];

    uint8_t skClient[OPAQUE_SHARED_SECRETBYTES];
    uint8_t authU[crypto_auth_hmacsha512_BYTES];
    uint8_t exportKeyLogin[crypto_hash_sha512_BYTES];

    OPAQUEClientFinalizeLogin(&cState, ke2, skClient, authU, exportKeyLogin);
    return ESP_OK;
}