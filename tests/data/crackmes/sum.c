#include "runtime.h"
__attribute__((noinline)) int check(const unsigned char *s) {
    unsigned sum=0; for(unsigned i=0;i<4;i++) sum+=s[i]; return sum==282;
}
#include "main.h"
