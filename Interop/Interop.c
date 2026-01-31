#include "Interop.h"
#include <string.h>

int HelloWorld(const char** out, int* outLen)
{
    if (!out || !outLen) { return 1; }

    static const char msg[] = "HelloWorld";
    *out = msg;
    *outLen = (int)(sizeof(msg) - 1);

    return 0;
}

int OpaqueInit(uint8_t sec[crypto_scalarmult_SCALARBYTES])
{
    return InitServer(sec);
}

int OpaqueRegister(const uint8_t alpha[crypto_core_ristretto255_BYTES], const uint8_t seed[crypto_scalarmult_SCALARBYTES], uint8_t rSec[OPAQUE_REGISTER_SECRET_LEN], uint8_t rPub[OPAQUE_REGISTER_PUBLIC_LEN])
{
    return OPAQUEServerAcceptRegistrationRequest(alpha, seed, rSec, rPub);
}

int OpaqueRegisterFinalize(const uint8_t rSec[OPAQUE_REGISTER_SECRET_LEN], const uint8_t registerRec[OPAQUE_REGISTRATION_RECORD_LEN], uint8_t rec[OPAQUE_USER_RECORD_LEN])
{
    return OPAQUEServerFinalizeRegistrationRequest(rSec, registerRec, rec);
}

int OpaqueLogin(const uint8_t ke1[OPAQUE_USER_SESSION_PUBLIC_LEN], const uint8_t rec[OPAQUE_USER_RECORD_LEN], const char* Username, uint8_t authU0[crypto_auth_hmacsha512_BYTES], uint8_t sk[OPAQUE_SHARED_SECRETBYTES], uint8_t ke2[OPAQUE_SERVER_SESSION_LEN])
{
    return OPAQUEServerAcceptLoginRequest(ke1, rec, Username, authU0, sk, ke2);
}

int OpaqueLoginVerify(const uint8_t authU0[crypto_auth_hmacsha512_BYTES], const uint8_t authU[crypto_auth_hmacsha512_BYTES])
{
    return OPAQUEServerLoginVerify(authU0, authU);
}