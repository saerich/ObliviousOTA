#ifndef __OPAQUE_H
#define __OPAQUE_H
#include <opaque.h>
#include <sodium.h>

typedef struct
{
    uint8_t* sec;
    uint16_t pwdLen;
} ClientState_t;

void OPAQUEInit(const char* UserId);
int OPAQUEClientRegister(const char* password, uint8_t alpha[crypto_core_ristretto255_BYTES], uint8_t** outSec, uint16_t* outPwdLen);
int OPAQUEClientFinalizeRegister(const uint8_t rPub[OPAQUE_REGISTER_PUBLIC_LEN], uint8_t* sec, uint16_t pwdLen, uint8_t regRec[OPAQUE_REGISTRATION_RECORD_LEN], uint8_t exportKey[crypto_hash_sha512_BYTES]);
int OPAQUEClientLogin(const char* password, ClientState_t* state, uint8_t ke1[OPAQUE_USER_SESSION_PUBLIC_LEN]);
int OPAQUEClientFinalizeLogin(ClientState_t* state, const uint8_t ke2[OPAQUE_SERVER_SESSION_LEN], uint8_t sk[OPAQUE_SHARED_SECRETBYTES], uint8_t authU[crypto_auth_hmacsha512_BYTES], uint8_t exportKey[crypto_hash_sha512_BYTES]);
#endif