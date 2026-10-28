#include "runtime.h"
__attribute__((noinline)) int check(const unsigned char *s) {
    const unsigned char expected[]={0x66,0x6d,0x63,0x64}; for(unsigned i=0;i<4;i++) if((s[i]^(32+i))!=expected[i]) return 0; return 1;
}
#include "main.h"
