__declspec(dllimport) int imported_value(int value);

int call_import(int value) { return imported_value(value) + 3; }

int large_frame(int index) {
    volatile signed char bytes[8192];
    bytes[index & 8191] = (signed char)index;
    return bytes[index & 8191];
}

double saved_xmm(double value) {
    return value + imported_value(7);
}

struct triple { unsigned long long a, b, c; };
struct triple make_triple(unsigned long long value) {
    struct triple result = {value, value + 1, value ^ 9};
    return result;
}

unsigned long long stack_arguments(unsigned long long a, unsigned long long b,
    unsigned long long c, unsigned long long d, unsigned long long e,
    unsigned long long f) {
    return a + 3 * b + 5 * c + 7 * d + 11 * e + 13 * f;
}
