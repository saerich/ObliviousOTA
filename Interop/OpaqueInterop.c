#include "OpaqueInterop.h"

void InitServer() { randombytes_buf(serverSecret, sizeof serverSecret); }

int OPAQUEServerAcceptRegistrationRequest(const uint8_t alpha[crypto_core_ristretto255_BYTES], uint8_t* rSec[OPAQUE_REGISTER_SECRET_LEN], uint8_t rPub[OPAQUE_REGISTER_PUBLIC_LEN])
{
    //No need to index if rsec valid, as if this returns -1 it is invalid.
    if(opaque_CreateRegistrationResponse(alpha, serverSecret, rSec, rPub) != 0) { return -1; }
    return 0;
}
