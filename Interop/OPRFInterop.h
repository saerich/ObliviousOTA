#ifndef OPRF_INTEROP_H
#define OPRF_INTEROP_H
#include <stdint.h>
#include <opaque.h>
#include <oprf/oprf.h>

int OPRFEvaluate(const uint8_t alpha[32], const uint8_t sk[OPAQUE_SHARED_SECRETBYTES], uint8_t beta[32]);

#endif