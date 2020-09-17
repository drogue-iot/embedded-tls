
#ifndef MBEDTLS_PLATFORM_ALT_H
#define MBEDTLS_PLATFORM_ALT_H

// TODO: shuffle this to .rs impl... extern?
typedef struct mbedtls_platform_context {

} mbedtls_platform_context;

#include <stdarg.h>
#include <stddef.h>

//#define MBEDTLS_PLATFORM_SNPRINTF_MACRO snprintf
#error fuck

extern int vsnprintf(char * restrict str, size_t size, const char * restrict format, va_list ap);
extern int snprintf(char * restrict str, size_t size, const char * restrict fmt, ...);

#endif // MBEDTLS_PLATFORM_ALT_H
