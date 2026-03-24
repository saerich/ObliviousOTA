#ifndef INTEROP_H
#define INTEROP_H

#include "OpaqueInterop.h"
#include "OPRFInterop.h"

__attribute__((visibility("default"))) int OpaqueInit(uint8_t serverSecret[crypto_scalarmult_SCALARBYTES]);
__attribute__((visibility("default"))) int OpaqueRegister(const uint8_t alpha[crypto_core_ristretto255_BYTES], const uint8_t seed[crypto_scalarmult_SCALARBYTES], uint8_t rSec[OPAQUE_REGISTER_SECRET_LEN], uint8_t rPub[OPAQUE_REGISTER_PUBLIC_LEN]);
__attribute__((visibility("default"))) int OpaqueRegisterFinalize(const uint8_t rSec[OPAQUE_REGISTER_SECRET_LEN], const uint8_t registerRec[OPAQUE_REGISTRATION_RECORD_LEN], uint8_t rec[OPAQUE_USER_RECORD_LEN]);
__attribute__((visibility("default"))) int OpaqueLogin(const uint8_t ke1[OPAQUE_USER_SESSION_PUBLIC_LEN], const uint8_t rec[OPAQUE_USER_RECORD_LEN], const char* Username, uint8_t authU0[crypto_auth_hmacsha512_BYTES], uint8_t sk[OPAQUE_SHARED_SECRETBYTES], uint8_t ke2[OPAQUE_SERVER_SESSION_LEN]);
__attribute__((visibility("default"))) int OpaqueLoginVerify(const uint8_t authU0[crypto_auth_hmacsha512_BYTES], const uint8_t authU[crypto_auth_hmacsha512_BYTES]);
__attribute__((visibility("default"))) int SelectOPRFEvaluate(const uint8_t alpha[32], const uint8_t sk[OPAQUE_SHARED_SECRETBYTES], uint8_t beta[32]);
__attribute__((visibility("default"))) int CreateKeyFromSKUKey(const uint8_t skClient[OPAQUE_SHARED_SECRETBYTES], const uint8_t deviceFirmwareKey[crypto_core_ristretto255_BYTES], uint8_t fwHash[crypto_hash_sha512_BYTES]);
__attribute__((visibility("default"))) int EncryptFirmware(const uint8_t slotNumber[4], const uint8_t blockNumber[4], const uint8_t skClient[OPAQUE_SHARED_SECRETBYTES], const uint8_t seed[crypto_scalarmult_SCALARBYTES], const uint8_t deviceKey[crypto_scalarmult_SCALARBYTES], const uint8_t firmwareBlock[1024], uint8_t nonce[12], uint8_t cipherText[1040]);
__attribute__((visibility("default"))) int EncryptFirmwareSize(const uint8_t skClient[OPAQUE_SHARED_SECRETBYTES], const uint8_t seed[crypto_scalarmult_SCALARBYTES], const uint8_t slotHash[64], const uint8_t firmwareLength[8], uint8_t nonce[12], uint8_t cipherText[24]);
/// @brief Not for interop, but used by firmware and internally, might get moved to utilities.
/// @param rwdU 
/// @param slotHash 
/// @param skClient 
/// @param aeadKey 
/// @return 
int CalculateFirmwareSizeKey(const uint8_t rwdU[64], const uint8_t slotHash[64], const uint8_t skClient[OPAQUE_SHARED_SECRETBYTES], uint8_t aeadKey[crypto_aead_chacha20poly1305_ietf_KEYBYTES]);
int CalculateFirmwareFileKey(const uint8_t rwdU[64], const uint8_t deviceKey[crypto_scalarmult_SCALARBYTES], const uint8_t skClient[OPAQUE_SHARED_SECRETBYTES], uint8_t aeadKey[crypto_aead_chacha20poly1305_ietf_KEYBYTES]);
int CalculateNonceKey(const uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES], const uint8_t rwdU[64], const uint8_t blockNumber[4], uint8_t nonceKey[crypto_aead_chacha20poly1305_ietf_NPUBBYTES]);
int CreateAAD(const uint8_t slotNumber[4], const uint8_t blockNumber[4], const uint8_t rwdU[64], uint8_t aad[72]);

#endif