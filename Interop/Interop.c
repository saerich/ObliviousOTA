#include "Interop.h"

int HelloWorld(const char** out, int* outLen)
{
    if (!out || !outLen) { return 1; }

    static const char msg[] = "Hello World";
    *out = msg;
    *outLen = (int)(sizeof(msg) - 1);
    
    return 0;
}