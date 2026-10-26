unsigned long long frame_bounds(unsigned long long seed) {
    volatile unsigned long long values[64];
    volatile unsigned long long *p = values;
    do {
        *p = seed;
        seed = seed * 1664525 + 1013904223;
        __asm__("" : "+r"(p));
        ++p;
    } while (p != values + 64);
    unsigned long long result = 0;
    p = values;
    do {
        result ^= *p;
        __asm__("" : "+r"(p));
        ++p;
    } while (p != values + 64);
    return result;
}
