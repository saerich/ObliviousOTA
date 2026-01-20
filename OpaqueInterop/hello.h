#ifndef HELLO_H
#define HELLO_H

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

#ifdef __cplusplus
extern "C"
{
#endif

	EXPORT int HelloWorld(const char** out, int* outLen);
		
#ifdef __cplusplus
}
#endif

#endif