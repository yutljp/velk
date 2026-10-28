#include "runtime.h"
__attribute__((noinline)) int check(const unsigned char *s) {
    return strtol((const char *)s,0,16)==0xface;
}
#include "main.h"
