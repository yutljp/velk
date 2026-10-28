#include "runtime.h"
__attribute__((noinline)) int check(const unsigned char *s) {
    return strcmp((const char *)s,"FLAG")==0;
}
#include "main.h"
