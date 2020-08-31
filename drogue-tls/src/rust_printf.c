/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#include <stdio.h>
#include <stdarg.h>

extern void mbedtls_log(const char* msg);

extern int mbedtls_printf(const char *fmt, ...) {
    va_list ap;

    va_start(ap,fmt);
    int n=vsnprintf(0,0,fmt,ap);
    va_end(ap);

    if (n<0)
       return -1;

    n++;
    char p[n];

    va_start(ap,fmt);
    n=vsnprintf(p,n,fmt,ap);
    va_end(ap);

    if (n<0)
       return -1;

    mbedtls_log(p);

    return n;
}
