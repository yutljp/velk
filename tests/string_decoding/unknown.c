#include "fixtures.c"

extern void external_event(void);
__attribute__((noinline)) void unknown_decoder(u8 *p, u32 n, u32 key) {
    xor_key(p,n,key);
    external_event();
}
u32 case_unknown_call(void) {
    unknown_decoder(xor_data, sizeof(xor_data), 93);
    return 0;
}

extern void *malloc(unsigned long size);
u32 case_heap(void) {
    u8 *p = malloc(sizeof(xor_data));
    if (!p) return 0;
    for (u32 i = 0; i < sizeof(xor_data); ++i) p[i] = xor_data[i];
    xor_key(p, sizeof(xor_data), 93);
    return p[0];
}
