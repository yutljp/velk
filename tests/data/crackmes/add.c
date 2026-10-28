#include "runtime.h"
__attribute__((noinline)) int check(const unsigned char *s) {
    const unsigned char expected[]={70,79,71,80}; for(unsigned i=0;i<4;i++) if((unsigned char)(s[i]+i*3)!=expected[i]) return 0; return 1;
}
#include "main.h"
