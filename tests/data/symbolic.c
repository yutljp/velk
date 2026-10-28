typedef unsigned long word;
volatile unsigned result;
__attribute__((noinline)) int success(void) { result = 73; return 73; }
__attribute__((noinline)) int failure(void) { result = 0; return 0; }
__attribute__((noinline)) int password(const unsigned char *p) {
    if (p[0] != 'v') return failure();
    if (p[1] != 'e') return failure();
    if (p[2] != 'l') return failure();
    if (p[3] != 'k') return failure();
    return success();
}
__attribute__((noinline)) int checksum(const unsigned char *p) {
    unsigned sum = 0;
    for (unsigned i = 0; i < 4; ++i) sum = sum * 3 + p[i];
    if (sum == 173) return success();
    return failure();
}
__attribute__((noinline)) int arguments(int argc, char **argv) {
    if (argc == 2 && argv[1][0] == 'y' && argv[1][1] == 'e' && argv[1][2] == 's') return success();
    return failure();
}
__attribute__((noinline)) int counted(const unsigned char *p) {
    unsigned sum = 0;
    for (unsigned i = 0; i < (p[0] & 7); ++i) sum += i;
    if (sum == 15) return success();
    return failure();
}
__attribute__((noinline)) int avoided(const unsigned char *p) {
    if ((p[0] & 255) > 255) return failure();
    if (p[0] == 42) return success();
    return 0;
}
__attribute__((noinline)) int indirect(const unsigned char *p) {
    const unsigned char values[4] = { 3, 8, 13, 21 };
    if (values[p[0] & 3] == 13) return success();
    return failure();
}
__attribute__((noinline)) int recurse(unsigned n) {
    if (n == 0) return success();
    if (n > 4) return failure();
    return recurse(n - 1);
}
__attribute__((noinline)) unsigned input_value(const unsigned char *p) { return p[0] * 3 + 1; }
__attribute__((noinline)) int nested(const unsigned char *p) {
    if (input_value(p) == 127) return success();
    return failure();
}
