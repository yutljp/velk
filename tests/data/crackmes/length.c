#include "runtime.h"
__attribute__((noinline)) int check(const unsigned char *s) {
    return strlen((const char *)s)==4 && memcmp(s,"FLAG",4)==0;
}
#include "main.h"
