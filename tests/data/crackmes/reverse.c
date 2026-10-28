#include "runtime.h"
__attribute__((noinline)) int check(const unsigned char *s) {
    unsigned char copy[5]; for(unsigned i=0;i<4;i++) copy[i]=s[3-i]; copy[4]=0; return strcmp((const char *)copy,"GALF")==0;
}
#include "main.h"
