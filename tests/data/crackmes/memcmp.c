#include "runtime.h"
__attribute__((noinline)) int check(const unsigned char *s) {
    return memcmp(s,"FLAG",4)==0;
}
#include "main.h"
