typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

uint64_t add64(uint64_t a, uint64_t b) { return a + b; }
uint64_t sub64(uint64_t a, uint64_t b) { return a - b; }
uint64_t mul64(uint64_t a, uint64_t b) { return a * b; }
uint64_t left64(uint64_t a, uint32_t n) { return a << (n & 63); }
uint64_t right64(uint64_t a, uint32_t n) { return a >> (n & 63); }
uint64_t mixed64(uint32_t tag, uint64_t a, uint32_t gap, uint64_t b) {
    return a + b + tag + gap;
}
uint64_t call64(uint64_t a, uint64_t b) { return add64(a, b) ^ 0x123456789abcdef0ULL; }
uint64_t div64(uint64_t a, uint64_t b) { return a / b; }
uint64_t mod64(uint64_t a, uint64_t b) { return a % b; }
uint64_t guarded_mod64(uint64_t a, uint64_t b) { return b ? a % b : a; }
uint64_t byte64(uint64_t a, uint32_t b) {
    volatile union { uint64_t value; unsigned char bytes[8]; } local;
    local.value = a + 1;
    local.bytes[0] = b;
    return local.value;
}
typedef long long int64_t;
int64_t signed_div64(int64_t a, int64_t b) { return a / b; }
int64_t signed_mod64(int64_t a, int64_t b) { return a % b; }

uint64_t guarded_sub64(uint64_t a, uint64_t b) {
    uint64_t sign = (uint64_t)1 << 63;
    uint64_t trial = (a ^ ((a ^ b) & sign)) - b;
    if (((a ^ b) & (trial ^ b)) & sign) return a;
    return a - b;
}
