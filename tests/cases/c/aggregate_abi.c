struct abi_pair { unsigned long long low, high; };
struct abi_mixed { double floating; unsigned long long integer; };
struct abi_hfa1 { double a; };
struct abi_hfa2 { double a, b; };
struct abi_hfa3 { double a, b, c; };
struct abi_hfa4 { double a, b, c, d; };
struct abi_triple { unsigned long long first, second, third; };
struct __attribute__((aligned(8))) abi_pair_aligned { unsigned long long low, high; };

_Static_assert(sizeof(struct abi_pair_aligned) == 16, "aligned pair size");
_Static_assert(_Alignof(struct abi_pair_aligned) == 8, "aligned pair alignment");

struct abi_pair abi_pair_adjust(struct abi_pair value, unsigned long long tail) {
    struct abi_pair result = { value.low + tail, value.high ^ tail };
    return result;
}

struct abi_mixed abi_mixed_adjust(struct abi_mixed value,
                                 unsigned long long delta, double bias) {
    struct abi_mixed result = { value.floating + bias, value.integer ^ delta };
    return result;
}

struct abi_hfa1 abi_hfa1_adjust(struct abi_hfa1 value, double bias) {
    value.a += bias;
    return value;
}

struct abi_hfa2 abi_hfa2_adjust(struct abi_hfa2 value, double bias) {
    value.b += bias;
    return value;
}

struct abi_hfa3 abi_hfa3_adjust(struct abi_hfa3 value, double bias) {
    value.c += bias;
    return value;
}

struct abi_hfa4 abi_hfa4_adjust(struct abi_hfa4 value, double bias) {
    value.d += bias;
    return value;
}

unsigned long long abi_exhaust_five(unsigned long long a, unsigned long long b,
                                   unsigned long long c, unsigned long long d,
                                   unsigned long long e, struct abi_pair value,
                                   unsigned long long tail) {
    return a + 3 * b + 5 * c + 7 * d + 11 * e
        + 13 * value.low + 17 * value.high + 19 * tail;
}

unsigned long long abi_exhaust_seven(unsigned long long a, unsigned long long b,
                                    unsigned long long c, unsigned long long d,
                                    unsigned long long e, unsigned long long f,
                                    unsigned long long g, struct abi_pair value,
                                    unsigned long long tail) {
    return a + 3 * b + 5 * c + 7 * d + 11 * e + 13 * f + 17 * g
        + 19 * value.low + 23 * value.high + 29 * tail;
}

struct abi_triple abi_indirect_make(struct abi_pair value, unsigned long long delta) {
    struct abi_triple result = {
        value.low + delta, value.high ^ delta, value.low - value.high
    };
    return result;
}

unsigned long long abi_exhaust_five_aligned(unsigned long long a, unsigned long long b,
                                           unsigned long long c, unsigned long long d,
                                           unsigned long long e, struct abi_pair_aligned value,
                                           unsigned long long tail) {
    return a + 3 * b + 5 * c + 7 * d + 11 * e
        + 13 * value.low + 17 * value.high + 19 * tail;
}

unsigned long long abi_exhaust_seven_aligned(unsigned long long a, unsigned long long b,
                                            unsigned long long c, unsigned long long d,
                                            unsigned long long e, unsigned long long f,
                                            unsigned long long g, struct abi_pair_aligned value,
                                            unsigned long long tail) {
    return a + 3 * b + 5 * c + 7 * d + 11 * e + 13 * f + 17 * g
        + 19 * value.low + 23 * value.high + 29 * tail;
}
