#ifndef __SSOT_H
#define __SSOT_H

#include <stdint.h>
#include <mbedtls/bignum.h>

#define NUMBER_OT 1000
#define BIT_SIZE 128
#define SECRET_BIT_SIZE 1
#define TEST_NUMBER 50

mbedtls_mpi** genKeys(int num, uint8_t** rndVal, int size);
uint8_t* secretSharing(size_t size, const uint8_t* secret, const uint8_t* rndVal, uint8_t** pShares);
mbedtls_mpi** encryptAndSwap(int size, const uint8_t* share, mbedtls_mpi** pair, mbedtls_mpi** rnd);
mbedtls_mpi* obliviousFilter(size_t size, const uint8_t* share, mbedtls_mpi** pair);
mbedtls_mpi* extractResult(int size, mbedtls_mpi* pResponse, const uint8_t* secretIndicies, mbedtls_mpi** keys);


mbedtls_mpi** genRandomMessages(int number, int size);

void freePairArray(mbedtls_mpi** arr, int n);
void freeVec(mbedtls_mpi* vector, int n);
#endif