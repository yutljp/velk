volatile unsigned data[4096] = {
    1, 2, 3, 4, 5, 0x12345678, 0x000000e8, 0, 0x000049e9, 0x0100e800,
    0xffe90000, 0x000000e9, 0, 0x0000850f, 0, 0x010000e8, 0x11110000,
    0x490000e9, 0x22220000
};
volatile unsigned result;

__attribute__((noinline)) unsigned add3(unsigned a, unsigned b, unsigned c) {
    return a + b + c;
}

#define DEFINE_PROBE(number) \
    __attribute__((noinline)) unsigned f##number(unsigned a) { \
        unsigned x = add3(a, number, a >> 3); \
        if (x & 1) x = add3(x, a, 17); \
        else x = add3(a, 7, x); \
        for (unsigned i = 0; i < 8; ++i) { \
            if ((x >> i) & 1) x = add3(x, i, a); \
            else x = x * 1664525u + 1013904223u; \
        } \
        return x; \
    }

DEFINE_PROBE(0)  DEFINE_PROBE(1)  DEFINE_PROBE(2)  DEFINE_PROBE(3)
DEFINE_PROBE(4)  DEFINE_PROBE(5)  DEFINE_PROBE(6)  DEFINE_PROBE(7)
DEFINE_PROBE(8)  DEFINE_PROBE(9)  DEFINE_PROBE(10) DEFINE_PROBE(11)
DEFINE_PROBE(12) DEFINE_PROBE(13) DEFINE_PROBE(14) DEFINE_PROBE(15)
DEFINE_PROBE(16) DEFINE_PROBE(17) DEFINE_PROBE(18) DEFINE_PROBE(19)
DEFINE_PROBE(20) DEFINE_PROBE(21) DEFINE_PROBE(22) DEFINE_PROBE(23)
DEFINE_PROBE(24) DEFINE_PROBE(25) DEFINE_PROBE(26) DEFINE_PROBE(27)
DEFINE_PROBE(28) DEFINE_PROBE(29) DEFINE_PROBE(30) DEFINE_PROBE(31)
DEFINE_PROBE(32) DEFINE_PROBE(33) DEFINE_PROBE(34) DEFINE_PROBE(35)
DEFINE_PROBE(36) DEFINE_PROBE(37) DEFINE_PROBE(38) DEFINE_PROBE(39)
DEFINE_PROBE(40) DEFINE_PROBE(41) DEFINE_PROBE(42) DEFINE_PROBE(43)
DEFINE_PROBE(44) DEFINE_PROBE(45) DEFINE_PROBE(46) DEFINE_PROBE(47)
DEFINE_PROBE(48) DEFINE_PROBE(49) DEFINE_PROBE(50) DEFINE_PROBE(51)
DEFINE_PROBE(52) DEFINE_PROBE(53) DEFINE_PROBE(54) DEFINE_PROBE(55)
DEFINE_PROBE(56) DEFINE_PROBE(57) DEFINE_PROBE(58) DEFINE_PROBE(59)
DEFINE_PROBE(60) DEFINE_PROBE(61) DEFINE_PROBE(62) DEFINE_PROBE(63)

__attribute__((noinline)) unsigned tail_call(unsigned a) {
    return f1(a);
}

__attribute__((noinline)) unsigned literal_bytes(void) {
    return 0x000000e9;
}

void start(void) {
    result = f0(data[0]) + f1(data[1]) + f15(data[2]);
    for (;;) {}
}
