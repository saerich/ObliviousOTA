#include "ssot.h"
#include <stdbool.h>
#include <stdlib.h>
#include <inttypes.h>
#include <freertos/FreeRTOS.h>
#include <esp_random.h>
#include <string.h>

/// @brief Implementation of equivalent of mpz_urandomb for mbedtls without initializing the mbedtls DRBG Context.
/// @param mpi mbedtls_mpi reference for setting the random value.
/// @param bits number of bits for the random value.
/// @return 0 if success, otherwise error code.
static int genMpiBits(mbedtls_mpi *mpi, int bits)
{
    mbedtls_mpi_init(mpi);

    size_t n = (bits + 7) / 8;
    uint8_t *buf = (uint8_t*)malloc(n);
    if(!buf) { return -1; }
    esp_fill_random(buf, n);

    int excess = (int)(n*8) - bits;

    if(excess > 0)
    {
        uint8_t mask = (uint8_t)(0xFFu >> excess);
        buf[0] &= mask;
    }

    bool zero = true;
    for(size_t i = 0; i<n; i++) 
    { 
        if(buf[i]) 
        { 
            zero = false; 
            break; 
        } 
    }
    if(zero) { buf[n - 1] = 1; } 
    
    int rc = mbedtls_mpi_read_binary(mpi, buf, n);
    free(buf);
    return rc;
}

typedef struct 
{
    size_t capacity;
    uint8_t* a;
    uint8_t* b;
    uint8_t* result;
} xorBaseState_t;

static xorBaseState_t gXor = {0};

static int ensureXorCapacity(size_t requirement)
{
    if(gXor.capacity >= requirement) { return 0; }
    size_t newCapacity = (requirement + 31u) & ~31u; //Align
    uint8_t* newA = heap_caps_realloc(gXor.a, newCapacity, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    uint8_t* newB = heap_caps_realloc(gXor.b, newCapacity, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    uint8_t* newR = heap_caps_realloc(gXor.result, newCapacity, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);

    if(!newA || !newB || !newR) { return -1; }
    gXor.a = newA;
    gXor.b = newB;
    gXor.result = newR;
    gXor.capacity = newCapacity;
    return 0;
}


/// @brief Replacement for mpz_xor using mbedtls_mpi, optimised for XTENSA
/// @param out 
/// @param a 
/// @param b 
/// @return 
static int mpiXor(mbedtls_mpi* out, const mbedtls_mpi* a, const mbedtls_mpi* b)
{
    mbedtls_mpi_init(out);

    size_t L = mbedtls_mpi_size(a);
    size_t lB = mbedtls_mpi_size(b);
    if(lB > L) { L = lB; }
    if(L == 0) { return 0; }

    if(ensureXorCapacity(L) != 0) 
    { 
        mbedtls_mpi_free(out);
        return -1;
    }

    memset(gXor.a, 0, L);
    memset(gXor.b, 0, L);
    
    if(mbedtls_mpi_write_binary(a, gXor.a, L) != 0 || mbedtls_mpi_write_binary(b, gXor.b, L) != 0)
    {
        mbedtls_mpi_free(out);
        return -1;
    }

    uint32_t* pA = (uint32_t*)gXor.a;
    uint32_t* pB = (uint32_t*)gXor.b;
    uint32_t* pR = (uint32_t*)gXor.result;
    size_t w = L / 4; //words
    size_t t = L & 3; //tail
    for(size_t i = 0; i < w; ++i) { pR[i] = pA[i] ^ pB[i]; }

    uint8_t* tA = (uint8_t*)(pA + w);
    uint8_t* tB = (uint8_t*)(pB + w);
    uint8_t* tR = (uint8_t*)(pR + w);
    for(size_t i = 0; i < t; ++i) { tR[i] = tA[i] ^ tB[i]; }
    return mbedtls_mpi_read_binary(out, gXor.result, L);
}

/// @brief Generates a number of random keys and random values of the size specified.
/// @param num Number of random keys and values to Generate.
/// @param rndVal Random value provided as reference.
/// @param size bitsize of the random keys and values.
/// @return random value generated from a uniform integer distribution.
mbedtls_mpi** genKeys(int num, uint8_t** rndVal, int size)
{
    mbedtls_mpi** rnd = ((mbedtls_mpi**)malloc(num * sizeof(mbedtls_mpi*)));
    if(!rnd) { return NULL; }
    if(rndVal) { *rndVal = NULL; }

    for(int i = 0; i < num; ++i)
    {
        rnd[i] = (mbedtls_mpi*)malloc(2 * sizeof(mbedtls_mpi));
        if(!rnd[i])
        {
            for(int j = 0; j < i; ++j)
            {
                mbedtls_mpi_free(&rnd[j][0]);
                mbedtls_mpi_free(&rnd[j][1]);
                free(rnd[j]);
            }    
            free(rnd);
            return NULL;           
            
        }

        if(genMpiBits(&rnd[i][0], size) != 0 || genMpiBits(&rnd[i][1], size) != 0)
        {
            mbedtls_mpi_free(&rnd[i][0]);
            mbedtls_mpi_free(&rnd[i][1]);
            free(rnd[i]);
            for (int j = 0; j < i; ++j)
            {
                mbedtls_mpi_free(&rnd[j][0]);
                mbedtls_mpi_free(&rnd[j][1]);
                free(rnd[j]);
            }
            free(rnd);
            return NULL;
        }
    }
    
    uint8_t* rndValInternal = (uint8_t*)malloc((size_t)num);
    if(!rndValInternal) 
    { 
        free(rndValInternal);
        freePairArray(rnd, num);
        return NULL; 
    }
    esp_fill_random(rndValInternal, (size_t)num);
    if(rndVal) { *rndVal = rndValInternal; }
    return rnd;
}

/// @brief XOR-based (2, 2) Secret Sharing Function from SS-OT paper / github.
/// @param size Size of the secret.
/// @param secret Secret to be Shared.
/// @param rndVal Random value for sharing.
/// @param pShares Pointer reference for the generated pShares.
/// @return sShares generated from the secret sharing.
uint8_t* secretSharing(size_t size, const uint8_t* secret, const uint8_t* rndVal, uint8_t** pShares)
{
    uint8_t *sShares = (uint8_t*)malloc(size);
    *pShares = (uint8_t*)malloc(size);
    if(!sShares || !*pShares) 
    { 
        free(sShares); 
        free(*pShares); 
        *pShares = NULL;
        return 0; 
    }
    for(size_t i = 0; i < size; ++i)
    {
        sShares[i] = rndVal[i] ^ secret[i];
        (*pShares)[i] = rndVal[i];
    }
    return sShares;
}

/// @brief Equivalent of Enc_and_Swap from SS-OT paper / github using mbedtls_mpi.
/// @param size 
/// @param share 
/// @param pair 
/// @param rnd 
/// @return 
mbedtls_mpi** encryptAndSwap(int size, const uint8_t* share, mbedtls_mpi** pair, mbedtls_mpi** rnd)
{
    mbedtls_mpi** result = (mbedtls_mpi**)malloc((size_t)size * sizeof(mbedtls_mpi*));
    if(!result)
    { 
        free(result); 
        return NULL; 
    }

    for(int i = 0; i < size; ++i)
    {
        result[i] = malloc(2 * sizeof(mbedtls_mpi));
        mbedtls_mpi_init(&result[i][0]);
        mbedtls_mpi_init(&result[i][1]);

        if(!result[i])
        {
            for(int j = 0; j < i; ++j)
            {
                if(result[j])
                {
                    mbedtls_mpi_free(&result[j][0]);
                    mbedtls_mpi_free(&result[j][1]);
                    free(result[j]);
                }
            }
            free(result);
            return NULL;
        }
        
        if(mpiXor(&result[i][0], &rnd[i][0], &pair[i][0]) != 0 || mpiXor(&result[i][1], &rnd[i][1], &pair[i][1]) != 0)
        {
            for(int j = 0; j <= i; ++j)
            {
                mbedtls_mpi_free(&result[j][0]);
                mbedtls_mpi_free(&result[j][1]);
                free(result[j]);
            }
            free(result);
            return NULL;            
        }

        unsigned char sel = (unsigned char)(share[i] & 1);
        if (mbedtls_mpi_safe_cond_swap(&result[i][0], &result[i][1], sel) != 0)
        {
            for (int j = 0; j <= i; ++j) 
            {
                mbedtls_mpi_free(&result[j][0]);
                mbedtls_mpi_free(&result[j][1]);
                free(result[j]);
            }
            free(result);
            return NULL;
        }
    }

    return result;
}

/// @brief Use mbedtls to create an oblivious filter over mbedtls_mpi, referenced SS-OT paper / github.
/// @param size 
/// @param share 
/// @param pair 
/// @return 
mbedtls_mpi* obliviousFilter(size_t size, const uint8_t* share, mbedtls_mpi** pair)
{
    mbedtls_mpi* result = (mbedtls_mpi*)malloc((size_t)size * sizeof(mbedtls_mpi));
    if(!result) { return NULL; }
    
    for(size_t i = 0; i < size; ++i)
    {
        mbedtls_mpi_init(&result[i]);
        
        if(mbedtls_mpi_copy(&result[i], &pair[i][0]) != 0)
        {
            for(size_t j = 0; j < i; ++j) { mbedtls_mpi_free(&result[j]); }
            free(result);
            return NULL;
        }
        unsigned char sel = (unsigned char)(share[i] & 1);
        if(mbedtls_mpi_safe_cond_assign(&result[i], &pair[i][1], sel) != 0)
        {
            for(size_t j = 0; j < i; ++j) { mbedtls_mpi_free(&result[j]); }
            mbedtls_mpi_free(&result[i]);
            free(result);
            return NULL;
        }
    }

    return result;
}

/// @brief Equivalent of extract_result from SS-OT paper / github using mbedtls_mpi.
/// @param size 
/// @param pResponse 
/// @param secretIndicies 
/// @param keys 
/// @return 
mbedtls_mpi* extractResult(int size, mbedtls_mpi* pResponse, const uint8_t* secretIndicies, mbedtls_mpi** keys)
{
    mbedtls_mpi* res = (mbedtls_mpi*)malloc((size_t)size * sizeof(mbedtls_mpi));
    if(!res) { return NULL; }

    for(int i = 0; i < size; ++i)
    {
        int index = (secretIndicies[i] & 1);
        if(mpiXor(&res[i], &pResponse[i], &keys[i][index]) != 0)
        {
            for(int j = 0; j <= i; ++j) { mbedtls_mpi_free(&res[j]); }
            free(res);
            return NULL;
        }
    }
    return res;
}

/// @brief Generates random message pairs for data.
/// @param number 
/// @param size 
/// @return 
mbedtls_mpi** genRandomMessages(int number, int size)
{
    mbedtls_mpi** rnd = malloc(number * sizeof(mbedtls_mpi*));
    if(!rnd) { return NULL; }

    for(int i = 0; i < number; ++i)
    {
        rnd[i] = malloc(2 * sizeof(mbedtls_mpi));
        if(!rnd[i])
        {
            for(int j = 0; j < i; ++j)
            {
                mbedtls_mpi_free(&rnd[j][0]);
                mbedtls_mpi_free(&rnd[j][1]);
                free(rnd[j]);
            }
            free(rnd);
            return NULL;
        }
        
        genMpiBits(&rnd[i][0], size);
        genMpiBits(&rnd[i][1], size);
    }
    return rnd;
}

/// @brief Safely frees an mbedtls_mpi** of pairs
/// @param arr Matrix / Array to free.
/// @param n Size of the array.
void freePairArray(mbedtls_mpi **arr, int n) 
{
    if (!arr) { return; }
    for (int i = 0; i < n; ++i) 
    {
        if (arr[i]) 
        {
            mbedtls_mpi_free(&arr[i][0]);
            mbedtls_mpi_free(&arr[i][1]);
            free(arr[i]);
        }
    }
    free(arr);
}

/// @brief Safely frees an mbedtls_mpi*
/// @param v Vector to free
/// @param n size of the vector
void freeVec(mbedtls_mpi *v, int n) 
{
    if (!v) { return; }
    for (int i = 0; i < n; ++i) { mbedtls_mpi_free(&v[i]); }
    free(v);
}