#include "runtime.h"
const unsigned long table_words[16] = {
    0, 1, 127, 128, 255, 256, 32767, 32768,
    65535, 65536, 0x7fffffff, 0x80000000,
    0xffffffff, 0x8000000000000000, 0xffffffffffffff80, 0xffffffffffffffff
};
__attribute__((noinline)) int check(const unsigned char *s) {
    static const unsigned char table[16]={9,2,14,7,1,12,3,11,5,0,15,6,10,8,4,13}; const unsigned char expected[]={3,10,2,11}; for(unsigned i=0;i<4;i++) if(table[s[i]&15]!=expected[i]) return 0; return 1;
}
#include "main.h"
