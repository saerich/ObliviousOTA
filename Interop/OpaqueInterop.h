#ifndef OPAQUEINTEROP_H
#define OPAQUEINTEROP_H
#include <opaque.h>
#include <sodium.H>
#include <stdbool.h>

// typedef struct
// {
//     uint8_t rSec[OPAQUE_REGISTER_SECRET_LEN];
//     bool rSecValid;
// } ServerRegistrationState_t;

static uint8_t serverSecret[crypto_scalarmult_SCALARBYTES];

int OPAQUEServerAcceptRegistrationRequest(const uint8_t alpha[crypto_core_ristretto255_BYTES], uint8_t* rSec[OPAQUE_REGISTER_SECRET_LEN], uint8_t rPub[OPAQUE_REGISTER_PUBLIC_LEN]);
#endif