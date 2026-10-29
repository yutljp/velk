#include "upx.c"

__declspec(dllimport) unsigned alpha(unsigned);
__declspec(dllimport) unsigned beta(unsigned);
__declspec(dllimport) unsigned combine(unsigned);

unsigned (*volatile pointer)(unsigned) = f3;
unsigned (*volatile pointers[3])(unsigned) = {f15, f31, f63};
struct __attribute__((packed)) {
    unsigned char tag;
    unsigned (*function)(unsigned);
} record = {1, f1};

void entry(void) {
    result = alpha(pointer(data[0])) + beta(data[1]) + combine(data[2]);
    for (;;) {}
}
