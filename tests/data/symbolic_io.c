extern int getchar(void);
extern long read(int, void *, unsigned long);
extern int success(void);
extern int failure(void);
__attribute__((noinline)) int getchar_password(void) {
    if (getchar() != 'v') return failure();
    if (getchar() != 'e') return failure();
    if (getchar() != 'l') return failure();
    if (getchar() != 'k') return failure();
    return success();
}
__attribute__((noinline)) int read_checksum(void) {
    unsigned char p[4];
    if (read(0, p, 4) != 4) return failure();
    unsigned sum = 0;
    for (unsigned i = 0; i < 4; ++i) sum = sum * 3 + p[i];
    if (sum == 173) return success();
    return failure();
}
