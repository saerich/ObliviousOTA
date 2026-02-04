#include "Interop.h"
#include <string.h>

int OpaqueInit(uint8_t sec[crypto_scalarmult_SCALARBYTES])
{
    return InitServer(sec);
}

int OpaqueRegister(const uint8_t alpha[crypto_core_ristretto255_BYTES], const uint8_t seed[crypto_scalarmult_SCALARBYTES], uint8_t rSec[OPAQUE_REGISTER_SECRET_LEN], uint8_t rPub[OPAQUE_REGISTER_PUBLIC_LEN])
{
    return OPAQUEServerAcceptRegistrationRequest(alpha, seed, rSec, rPub);
}

int OpaqueRegisterFinalize(const uint8_t rSec[OPAQUE_REGISTER_SECRET_LEN], const uint8_t registerRec[OPAQUE_REGISTRATION_RECORD_LEN], uint8_t rec[OPAQUE_USER_RECORD_LEN])
{
    return OPAQUEServerFinalizeRegistrationRequest(rSec, registerRec, rec);
}

int OpaqueLogin(const uint8_t ke1[OPAQUE_USER_SESSION_PUBLIC_LEN], const uint8_t rec[OPAQUE_USER_RECORD_LEN], const char* Username, uint8_t authU0[crypto_auth_hmacsha512_BYTES], uint8_t sk[OPAQUE_SHARED_SECRETBYTES], uint8_t ke2[OPAQUE_SERVER_SESSION_LEN])
{
    return OPAQUEServerAcceptLoginRequest(ke1, rec, Username, authU0, sk, ke2);
}

int OpaqueLoginVerify(const uint8_t authU0[crypto_auth_hmacsha512_BYTES], const uint8_t authU[crypto_auth_hmacsha512_BYTES])
{
    return OPAQUEServerLoginVerify(authU0, authU);
}

int SelectOPRFEvaluate(const uint8_t alpha[32], const uint8_t sk[OPAQUE_SHARED_SECRETBYTES], uint8_t beta[32])
{
    return OPRFEvaluate(alpha, sk, beta);
}

int CreateKeyFromSKUKey(const uint8_t skClient[OPAQUE_SHARED_SECRETBYTES], const uint8_t deviceFirmwareKey[crypto_core_ristretto255_BYTES], uint8_t fwHash[crypto_hash_sha512_BYTES])
{
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    static const char* firmwareDomain = "fw";
    crypto_hash_sha512_update(&st, (const uint8_t*)firmwareDomain, (uint16_t)strlen(firmwareDomain));
    crypto_hash_sha512_update(&st, skClient, OPAQUE_SHARED_SECRETBYTES); // Since the shared key is known by both the server and client, it's safe to use.
    crypto_hash_sha512_update(&st, deviceFirmwareKey, crypto_core_ristretto255_BYTES); //Firmware key.
    crypto_hash_sha512_final(&st, fwHash);

    return 0;
}

int EncryptFirmware(const uint8_t skClient[OPAQUE_SHARED_SECRETBYTES], const uint8_t seed[crypto_scalarmult_SCALARBYTES], const uint8_t deviceKey[crypto_scalarmult_SCALARBYTES], const uint8_t firmwareBlock[1024], uint8_t nonce[12], uint8_t cipherText[1040])
{
    uint8_t P[crypto_core_ristretto255_BYTES];
    voprf_hash_to_group(deviceKey, crypto_scalarmult_SCALARBYTES, P);

    uint8_t N[crypto_core_ristretto255_BYTES];
    if(crypto_scalarmult_ristretto255(N, seed, P) != 0) { return -1; }
    
    uint8_t rwdU[64];
    oprf_Finalize(deviceKey, crypto_scalarmult_SCALARBYTES, N, rwdU);

    uint8_t aeadKey[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    crypto_generichash_state st;
    static const char* firmwareFileDomain = "firmwareFile";
    crypto_generichash_init(&st, NULL, 0, 32);
    crypto_generichash_update(&st, (const uint8_t*) firmwareFileDomain, strlen(firmwareFileDomain));
    crypto_generichash_update(&st, rwdU, 64);
    crypto_generichash_update(&st, deviceKey, crypto_scalarmult_SCALARBYTES);
    crypto_generichash_update(&st, skClient, OPAQUE_SHARED_SECRETBYTES);
    crypto_generichash_final(&st, aeadKey, 32);

    randombytes_buf(nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    unsigned long long cLen = 0;
    if(crypto_aead_chacha20poly1305_ietf_encrypt(cipherText, &cLen, firmwareBlock, 1024, NULL, 0, NULL, nonce, aeadKey) != 0) { return -1; }
    
    memset(P, 0, sizeof(P));
    memset(N, 0, sizeof(N));
    memset(rwdU, 0, sizeof(rwdU));
    memset(aeadKey, 0, sizeof(aeadKey));

    return cLen == 1040 ? 0 : -1;

}

int EncryptFirmwareSize(const uint8_t skClient[OPAQUE_SHARED_SECRETBYTES], const uint8_t seed[crypto_scalarmult_SCALARBYTES], const uint8_t slotHash[64], const uint8_t firmwareLength[8], uint8_t nonce[12], uint8_t cipherText[24])
{
    uint8_t P[crypto_core_ristretto255_BYTES];
    voprf_hash_to_group(slotHash, 64, P);

    uint8_t N[crypto_core_ristretto255_BYTES];
    if(crypto_scalarmult_ristretto255(N, seed, P) != 0) { return -1; }
    
    uint8_t rwdU[64];
    oprf_Finalize(slotHash, 64, N, rwdU);

    uint8_t aeadKey[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    crypto_generichash_state st;
    static const char* firmwareSzDomain = "firmwareSize";
    crypto_generichash_init(&st, NULL, 0, 32);
    crypto_generichash_update(&st, (const uint8_t*) firmwareSzDomain, strlen(firmwareSzDomain));
    crypto_generichash_update(&st, rwdU, 64);
    crypto_generichash_update(&st, slotHash, 64);
    crypto_generichash_update(&st, skClient, OPAQUE_SHARED_SECRETBYTES);
    crypto_generichash_final(&st, aeadKey, 32);

    randombytes_buf(nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    unsigned long long cLen = 0;
    if(crypto_aead_chacha20poly1305_ietf_encrypt(cipherText, &cLen, firmwareLength, 8, NULL, 0, NULL, nonce, aeadKey) != 0) { return -1; }
    
    memset(P, 0, sizeof(P));
    memset(N, 0, sizeof(N));
    memset(rwdU, 0, sizeof(rwdU));
    memset(aeadKey, 0, sizeof(aeadKey));

    return cLen == (24) ? 0 : -1;

}