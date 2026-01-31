#ifndef __HTTP_H
#define __HTTP_H
#include <cJSON.h>
#include <stdint.h>

typedef struct 
{
    char* buf;
    int bufLen;
    int bufSize;
} HTTPBufferContext_t;

cJSON* HTTPGetJSON(const char* url, int* statusCode);
void HTTPGet(const char* url, int* statusCode);
void URLEncodeByteArray(const uint8_t* data, size_t len, char* out, size_t outSize);
#endif