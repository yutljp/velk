#include "runtime.h"
__attribute__((noinline)) static int first(const unsigned char *s) { return s[0]==70 && s[1]==76; }
__attribute__((noinline)) static int last(const unsigned char *s) { return s[2]==65 && s[3]==71; }
__attribute__((noinline)) static int nested(const unsigned char *s) { return first(s) && last(s); }
__attribute__((noinline)) int check(const unsigned char *s) {
    return nested(s);
}
#include "main.h"
