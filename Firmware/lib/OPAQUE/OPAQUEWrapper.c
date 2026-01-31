#include "OPAQUEWrapper.h"
#include <esp_err.h>
#include <stdbool.h>
#include <esp_log.h>

static const char* ServerId = "314159265359";
static const char* Context = "BlindFetch/OPAQUE";
Opaque_Ids ids;

void OPAQUEInit(const char* UserId)
{
    if(sodium_init() < 0) { ESP_ERROR_CHECK(ESP_ERR_HW_CRYPTO_BASE); } 
    ids.idU_len = (uint16_t)strlen(UserId);
    ids.idU = (uint8_t*)UserId;
    ids.idS_len = (uint16_t)strlen(ServerId);
    ids.idS = (uint8_t*)ServerId;
}

int OPAQUEClientRegister(const char* password, uint8_t alpha[crypto_core_ristretto255_BYTES], uint8_t** outSec, uint16_t* outPwdLen)
{
    const uint16_t pwdLen = (uint16_t)strlen(password);
    const uint8_t *pwd = (const uint8_t*) password;

    uint8_t *sec = malloc(OPAQUE_REGISTER_USER_SEC_LEN + pwdLen);
    if(!sec) { return -1; }
    int oRes = opaque_CreateRegistrationRequest(pwd, pwdLen, sec, alpha);
    if(oRes != 0)
    {
        ESP_LOGI("GENERAL", "OPAQUE Registration Request failed. %d", oRes);
        free(sec);
        return -1;
    }

    *outSec = sec;
    *outPwdLen = pwdLen;
    return 0;
}

int OPAQUEClientFinalizeRegister(const uint8_t rPub[OPAQUE_REGISTER_PUBLIC_LEN], uint8_t* sec, uint16_t pwdLen, uint8_t regRec[OPAQUE_REGISTRATION_RECORD_LEN], uint8_t exportKey[crypto_hash_sha512_BYTES])
{
    if(opaque_FinalizeRequest(sec, rPub, &ids, regRec, exportKey) != 0) { return -1; }

    sodium_memzero(sec, OPAQUE_REGISTER_USER_SEC_LEN + pwdLen);
    free(sec);
    return 0;
}

int OPAQUEClientLogin(const char* password, ClientState_t* state, uint8_t ke1[OPAQUE_USER_SESSION_PUBLIC_LEN])
{
    const uint16_t pwdLen = (uint16_t)strlen(password);
    const uint8_t *pwd = (const uint8_t*) password;

    state->sec = malloc(OPAQUE_USER_SESSION_SECRET_LEN + pwdLen);
    if(!state->sec) { return -1; }
    state->pwdLen = pwdLen;

    if(opaque_CreateCredentialRequest(pwd, pwdLen, state->sec, ke1) != 0)
    {
        free(state->sec);
        state->sec = NULL;
        return -1;
    }
    return 0;
}

int OPAQUEClientFinalizeLogin(ClientState_t* state, const uint8_t ke2[OPAQUE_SERVER_SESSION_LEN], uint8_t sk[OPAQUE_SHARED_SECRETBYTES], uint8_t authU[crypto_auth_hmacsha512_BYTES], uint8_t exportKey[crypto_hash_sha512_BYTES])
{
    if(!state || !state->sec) { return -1; }

    const uint8_t* context = (const uint8_t*)Context;
    const uint16_t contextLen = (uint16_t)strlen(Context);

    if(opaque_RecoverCredentials(ke2, state->sec, context, contextLen, &ids, sk, authU, exportKey) != 0) { return -1; }
    sodium_memzero(state->sec, OPAQUE_USER_SESSION_SECRET_LEN + state->pwdLen);
    free(state->sec);
    return 0;
}