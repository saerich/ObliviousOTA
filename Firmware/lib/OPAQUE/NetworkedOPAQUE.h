#ifndef NETWORKED_OPAQUE_H
#include "OPAQUEWrapper.h"
#include <esp_err.h>
#include <stdbool.h>
#include <esp_log.h>

esp_err_t NetworkedOPAQUERegister(const char* opaqueServerUrl, const char* username, const char* password);
esp_err_t NetworkedOPAQUELogin(const char* password);
#endif