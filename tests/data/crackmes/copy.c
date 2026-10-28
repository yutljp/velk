#include "runtime.h"
__attribute__((noinline)) int check(const unsigned char *s) {
    unsigned char copy[5]; memcpy(copy,s,4); copy[4]=0; return strcmp((const char *)copy,"FLAG")==0;
}
#include "main.h"
