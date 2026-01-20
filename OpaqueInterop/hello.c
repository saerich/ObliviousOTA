#include "hello.h"

int HelloWorld(const char** out, int* outLen)
{
	*out = "Hello World";
	*outLen = sizeof("Hello World")-1;
	return 0;
}