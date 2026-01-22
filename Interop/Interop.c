#include "Interop.h"

int HelloWorld(const char** out, int* outLen)
{
    if (!out || !outLen) { return 1; }

    static const char msg[] = "HelloWorld";
    *out = msg;
    *outLen = (int)(sizeof(msg) - 1);

    return 0;
}

int OpaqueRegister(const uint8_t alpha[crypto_core_ristretto255_BYTES], uint8_t* rSec[OPAQUE_REGISTER_SECRET_LEN], uint8_t rPub[OPAQUE_REGISTER_PUBLIC_LEN])
{
    return OPAQUEServerAcceptRegistrationRequest(alpha, rSec, rPub);
}