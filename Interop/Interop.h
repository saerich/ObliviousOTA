#ifndef INTEROP_H
#define INTEROP_H

#include "OpaqueInterop.h"

__declspec(dllexport) int HelloWorld(const char** out, int* outLen);
__declspec(dllexport) int OpaqueRegister(const uint8_t alpha[crypto_core_ristretto255_BYTES], uint8_t* rSec[OPAQUE_REGISTER_SECRET_LEN], uint8_t rPub[OPAQUE_REGISTER_PUBLIC_LEN]);


#endif