#include "OpaqueInterop.h"
#include <sodium.h>
#include <string.h>

static const char* Context = "BlindFetch/OPAQUE";
static const char* ServerId = "314159265359";

int InitServer(uint8_t serverSecret[crypto_scalarmult_SCALARBYTES])
{
    if(sodium_init() < 0) { return -1; }
    randombytes_buf(serverSecret, crypto_scalarmult_SCALARBYTES);
    return 0;
}

int OPAQUEServerAcceptRegistrationRequest(const uint8_t alpha[crypto_core_ristretto255_BYTES], const uint8_t seed[crypto_scalarmult_SCALARBYTES], uint8_t rSec[OPAQUE_REGISTER_SECRET_LEN], uint8_t rPub[OPAQUE_REGISTER_PUBLIC_LEN])
{
    if(opaque_CreateRegistrationResponse(alpha, seed, rSec, rPub) != 0) { return -1; }
    return 0;
}

int OPAQUEServerFinalizeRegistrationRequest(const uint8_t rSec[OPAQUE_REGISTER_SECRET_LEN], const uint8_t registerRec[OPAQUE_REGISTRATION_RECORD_LEN], uint8_t rec[OPAQUE_USER_RECORD_LEN]) 
{
    opaque_StoreUserRecord(rSec, registerRec, rec);
    return 0;
}

int OPAQUEServerAcceptLoginRequest(const uint8_t ke1[OPAQUE_USER_SESSION_PUBLIC_LEN], const uint8_t rec[OPAQUE_USER_RECORD_LEN], const char* Username, uint8_t authU0[crypto_auth_hmacsha512_BYTES], uint8_t sk[OPAQUE_SHARED_SECRETBYTES], uint8_t ke2[OPAQUE_SERVER_SESSION_LEN])
{
    Opaque_Ids ids = 
    {
        .idS_len = (uint16_t)strlen(ServerId),
        .idS = (uint8_t*)ServerId,
        .idU_len = (uint16_t)strlen(Username),
        .idU = (uint8_t*)Username
    };
    const uint8_t* context = (const uint8_t*)Context;
    const uint16_t contextLen = (uint16_t)strlen(Context);
    if(opaque_CreateCredentialResponse(ke1, rec, &ids, context, contextLen, ke2, sk, authU0) != 0) { return -1; }
    return 0;
}

int OPAQUEServerLoginVerify(const uint8_t authU0[crypto_auth_hmacsha512_BYTES], const uint8_t authU[crypto_auth_hmacsha512_BYTES])
{
    if(opaque_UserAuth(authU0, authU) != 0) { return -1; }
    return 0;
}