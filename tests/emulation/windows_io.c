typedef __SIZE_TYPE__ size_t;
extern int printf(const char *, ...);
extern int sscanf(const char *, const char *, ...);

__declspec(dllexport) int print_long(void) {
    return printf("%ld|%zu", -1L, (size_t)-1);
}
__declspec(dllexport) int scan_long(void) {
    struct { long value; unsigned marker; } state = {0, 0x12345678};
    int count = sscanf("-27", "%ld", &state.value);
    return count == 1 && state.value == -27 && state.marker == 0x12345678;
}

_Static_assert(sizeof(long) == 4, "Windows ARM64 requires a four-byte long.");
_Static_assert(sizeof(void *) == 8, "Windows ARM64 requires eight-byte pointers.");
__declspec(dllexport) __attribute__((naked)) int invoke_import(void) {
    __asm__("str x30, [sp, #-16]!\nblr x16\nldr x30, [sp], #16\nret");
}
