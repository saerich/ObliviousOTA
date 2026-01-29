#ifndef INTEROP_H
#define INTEROP_H

#include "OpaqueInterop.h"

__attribute__((visibility("default"))) int OpaqueInit(uint8_t serverSecret[crypto_scalarmult_SCALARBYTES]);
__attribute__((visibility("default"))) int HelloWorld(const char** out, int* outLen);
__attribute__((visibility("default"))) int OpaqueRegister(const uint8_t alpha[crypto_core_ristretto255_BYTES], const uint8_t seed[crypto_scalarmult_SCALARBYTES], uint8_t rSec[OPAQUE_REGISTER_SECRET_LEN], uint8_t rPub[OPAQUE_REGISTER_PUBLIC_LEN]);
__attribute__((visibility("default"))) int OpaqueRegisterFinalize(const uint8_t rSec[OPAQUE_REGISTER_SECRET_LEN], const uint8_t registerRec[OPAQUE_REGISTRATION_RECORD_LEN], uint8_t rec[OPAQUE_USER_RECORD_LEN]);

#endif