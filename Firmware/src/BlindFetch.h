#ifndef BLIND_FETCH_H
#define BLIND_FETCH_H
#include <opaque.h>
#include <oprf/oprf.h>

void BlindDownloadFirmware(const char* downloadServerURL, const char* deviceFirmwareKey, const char* username, const uint8_t skClient[OPAQUE_SHARED_SECRETBYTES]);
void OTAHeaderGeneration(const char* downloadServerURL, const char* deviceFirmwareKey, const char* username, const uint8_t skClient[OPAQUE_SHARED_SECRETBYTES]);

#ifdef PlainOTA
uint64_t PlainOTADownload(const char* downloadURL);
#endif
#endif