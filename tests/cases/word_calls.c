typedef unsigned int uint32_t;

extern uint32_t __aeabi_uidiv(uint32_t, uint32_t);
extern int __aeabi_idiv(int, int);

uint32_t divide_unsigned(uint32_t a, uint32_t b) {
    return __aeabi_uidiv(a, b);
}

int divide_signed(int a, int b) {
    return __aeabi_idiv(a, b);
}

uint32_t indexed_frame(uint32_t n) {
    uint32_t values[8];
    for (uint32_t i = 0; i < 8; ++i) {
        values[i] = n + i;
    }
    return values[n & 7];
}

uint32_t remainder_unsigned(uint32_t a, uint32_t b) { return a % b; }
int remainder_signed(int a, int b) { return a % b; }
uint32_t scalar_words(uint32_t a, uint32_t b, uint32_t c, uint32_t d) { return (a + b) ^ (c + d); }

uint32_t advancing_buffers(uint32_t n) {
    uint32_t words[120];
    volatile unsigned short tags[9];
    for (uint32_t i = 0; i < 120; ++i) words[i] = n + i;
    for (uint32_t i = 0; i < 9; ++i) tags[i] = i + 3;
    return words[n % 120] + tags[n % 9];
}
