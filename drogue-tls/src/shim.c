
#include <stdarg.h>
#include <stddef.h>

extern int platform_vsnprintf(char * restrict str, size_t size, const char * restrict format, va_list ap);
extern int platform_snprintf(char * restrict str, size_t size, const char * restrict fmt, ...) {
    va_list ap;
    int n;

    //va_start(ap,fmt);
    //int n=platform_vsnprintf(0,0,fmt,ap);
    //va_end(ap);

    //if (n<0)
       //return -1;

    //n++;
    //char p[n];

    va_start(ap,fmt);
    n=platform_vsnprintf(str,size,fmt,ap);
    va_end(ap);

    //if (n<0)
       //return -1;

    //mbedtls_log(p);

    return n;
}