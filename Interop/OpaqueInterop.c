#include "OpaqueInterop.h"
#include <sodium.h>
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

int OPAQUEServerFinalizeRegistrationRequest(uint8_t rSec[OPAQUE_REGISTER_SECRET_LEN], const uint8_t registerRec[OPAQUE_REGISTRATION_RECORD_LEN], uint8_t rec[OPAQUE_USER_RECORD_LEN]) 
{
    opaque_StoreUserRecord(rSec, registerRec, rec);
    return 0;
}