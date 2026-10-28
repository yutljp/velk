#include "runtime.h"
__attribute__((noinline)) int check(const unsigned char *s) {
    const unsigned char expected[]={140,49,10,116}; for(unsigned i=0;i<4;i++){unsigned n=i+1; if((unsigned char)((s[i]<<n)|(s[i]>>(8-n)))!=expected[i]) return 0;} return 1;
}
#include "main.h"
