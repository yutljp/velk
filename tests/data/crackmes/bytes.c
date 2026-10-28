#include "runtime.h"
__attribute__((noinline)) int check(const unsigned char *s) {
    return s[0]=='F' && s[1]=='L' && s[2]=='A' && s[3]=='G';
}
#include "main.h"
