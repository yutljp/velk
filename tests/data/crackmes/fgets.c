#include "runtime.h"
#define INPUT_FGETS
__attribute__((noinline)) int check(const unsigned char *s) {
    return strncmp((const char *)s,"FLAG",4)==0;
}
#include "main.h"
