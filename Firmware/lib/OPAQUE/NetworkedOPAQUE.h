#ifndef NETWORKED_OPAQUE_H
#include "OPAQUEWrapper.h"
#include <esp_err.h>
#include <stdbool.h>
#include <esp_log.h>

esp_err_t NetworkedOPAQUERegister(const char* opaqueServerUrl, const char* username, const char* password);
esp_err_t NetworkedOPAQUELogin(const char* opaqueServerUrl, const char* username, const char* password, uint8_t skClient[OPAQUE_SHARED_SECRETBYTES], uint8_t exportKeyLogin[crypto_hash_sha512_BYTES]);
#endif