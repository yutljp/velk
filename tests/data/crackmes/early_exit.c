#include "runtime.h"
__attribute__((noinline)) int check(const unsigned char *s) {
    for(unsigned i=0;i<4;i++) if(s[i]!=(unsigned char)"FLAG"[i]) return 0; return 1;
}
#include "main.h"
