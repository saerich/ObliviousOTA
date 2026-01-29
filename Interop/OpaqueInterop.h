#ifndef OPAQUEINTEROP_H
#define OPAQUEINTEROP_H
#include <opaque.h>
#include <sodium.h>
#include <stdbool.h>

int InitServer(uint8_t serverSecret[crypto_scalarmult_SCALARBYTES]);
int OPAQUEServerAcceptRegistrationRequest(const uint8_t alpha[crypto_core_ristretto255_BYTES], const uint8_t seed[crypto_scalarmult_SCALARBYTES], uint8_t rSec[OPAQUE_REGISTER_SECRET_LEN], uint8_t rPub[OPAQUE_REGISTER_PUBLIC_LEN]);
int OPAQUEServerFinalizeRegistrationRequest(uint8_t rSec[OPAQUE_REGISTER_SECRET_LEN], const uint8_t registerRec[OPAQUE_REGISTRATION_RECORD_LEN], uint8_t rec[OPAQUE_USER_RECORD_LEN]);

#endif