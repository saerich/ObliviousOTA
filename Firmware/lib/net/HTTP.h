#ifndef __HTTP_H
#define __HTTP_H
#include <cJSON.h>
#include <stdint.h>
#include <esp_err.h>
#include <esp_http_client.h>

typedef struct 
{
    char* buf;
    int bufLen;
    int bufSize;
} HTTPBufferContext_t;

cJSON* HTTPGetJSON(const char* url, int* statusCode);
void HTTPGet(const char* url, int* statusCode);
void URLEncodeByteArray(const uint8_t* data, size_t len, char* out, size_t outSize);
void URLDecodeHexString(const char* hexString, uint8_t* output);
esp_err_t TLSPost(const char* baseURL, const char* path, const uint8_t* postBody, const size_t bodySize, esp_http_client_handle_t* client, int* statusCode);
int ResponseReadUpTo(esp_http_client_handle_t client, uint8_t* buf, int len);
void HttpFree(esp_http_client_handle_t *client);
esp_err_t ResponseDiscard(esp_http_client_handle_t client, size_t total);

#endif