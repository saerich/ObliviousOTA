#include "OPRFInterop.h"

int OPRFEvaluate(const uint8_t alpha[32], const uint8_t sk[OPAQUE_SHARED_SECRETBYTES], uint8_t beta[32])
{
    return oprf_Evaluate(sk, alpha, beta);
}