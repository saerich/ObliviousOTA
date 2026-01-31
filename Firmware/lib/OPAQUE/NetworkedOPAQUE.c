#include "NetworkedOPAQUE.h"
#include <esp_err.h>
#include <stdbool.h>
#include <esp_log.h>
#include <HTTP.h>

// static const char* Context = "BlindFetch/OPAQUE";
// static const char* ServerId = "314159265359";

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
    memset(url, 0x00, sizeof(url));

    if(statusCode != 200) { return ESP_ERR_NOT_SUPPORTED; } //Already registered.

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
    
    snprintf(url, sizeof(url), "%s/RegisterFinalize?RegisterRecord=%s&Username=%s", opaqueServerUrl, encodedRegRec, username);
    HTTPGet(url, &statusCode);
    memset(url, 0x00, sizeof(url));

    //if statuscode 200, probably save something to NVS to just say "I've registered!";

    return ESP_OK;
}

esp_err_t NetworkedOPAQUELogin(const char* opaqueServerUrl, const char* username, const char* password, uint8_t skClient[OPAQUE_SHARED_SECRETBYTES], uint8_t exportKeyLogin[crypto_hash_sha512_BYTES])
{
    ClientState_t cState = {0};
    uint8_t ke1[OPAQUE_USER_SESSION_PUBLIC_LEN];
    OPAQUEClientLogin(password, &cState, ke1);

    char encodedKE1[sizeof(ke1)*2+1];
    URLEncodeByteArray(ke1, sizeof(ke1), encodedKE1, sizeof(encodedKE1));

    char url[1024];
    int statusCode = 0;
    snprintf(url, sizeof(url), "%s/Login?Ke1=%s&Username=%s", opaqueServerUrl, encodedKE1, username);

    cJSON* loginRes = HTTPGetJSON(url, &statusCode);
    const char* ke2Str = cJSON_GetStringValue(loginRes);
    uint8_t ke2[OPAQUE_SERVER_SESSION_LEN];
    for(size_t i = 0; i < strlen(ke2Str)/2; i++) { sscanf(ke2Str + (i*2), "%2hhx", &ke2[i]); }
    cJSON_Delete(loginRes);
    memset(url, 0x00, sizeof(url));

    uint8_t authU[crypto_auth_hmacsha512_BYTES];

    OPAQUEClientFinalizeLogin(&cState, ke2, skClient, authU, exportKeyLogin);
    
    char encodedAuthU[sizeof(authU)*2+1];
    URLEncodeByteArray(authU, sizeof(authU), encodedAuthU, sizeof(encodedAuthU));
    snprintf(url, sizeof(url), "%s/LoginVerify?AuthU=%s&Username=%s", opaqueServerUrl, encodedAuthU, username);
    HTTPGet(url, &statusCode);

    return (statusCode >= 200 && statusCode <= 300) ? ESP_OK : ESP_ERR_INVALID_RESPONSE;
}