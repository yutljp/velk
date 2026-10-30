typedef __SIZE_TYPE__ size_t;
typedef __UINTPTR_TYPE__ word;
#define API __declspec(dllimport)
#define EXPORT __declspec(dllexport)
API void __stdcall ExitProcess(unsigned);
#ifdef UCRT
#include "windows_ucrt.h"
API void *__stdcall GetModuleHandleA(const char *);
API void *__stdcall GetProcAddress(void *, const char *);
#else
API int printf(const char *, ...);
API int fprintf(void *, const char *, ...);
API int sprintf(char *, const char *, ...);
API int vsprintf(char *, const char *, __builtin_va_list);
API int sscanf(const char *, const char *, ...);
#endif
API int puts(const char *);
API int putchar(int);
API void *malloc(size_t);
API void *calloc(size_t, size_t);
API void free(void *);
API void *memcpy(void *, const void *, size_t);
API void *memmove(void *, const void *, size_t);
API void *memset(void *, int, size_t);
API int memcmp(const void *, const void *, size_t);
API void *memchr(const void *, int, size_t);
API size_t strlen(const char *);
API size_t strnlen(const char *, size_t);
API int strcmp(const char *, const char *);
API int strncmp(const char *, const char *, size_t);
API char *strcpy(char *, const char *);
API char *strncpy(char *, const char *, size_t);
API char *strchr(const char *, int);
API size_t strcspn(const char *, const char *);
API int atoi(const char *);
API int toupper(int);
API int tolower(int);
API void *fopen(const char *, const char *);
API int fclose(void *);
API int fflush(void *);
API int setvbuf(void *, char *, int, size_t);
API int fputs(const char *, void *);
API size_t fwrite(const void *, size_t, size_t, void *);
API size_t fread(void *, size_t, size_t, void *);
API char *fgets(char *, int, void *);
API int feof(void *);
API int ferror(void *);
API int rand(void);

#ifdef UCRT
EXPORT unsigned crt_exports(void) {
    void *module = GetModuleHandleA("ucrtbase.dll");
    return module && GetProcAddress(module, "__stdio_common_vfprintf")
        && GetProcAddress(module, "__stdio_common_vsprintf")
        && GetProcAddress(module, "__stdio_common_vsscanf")
        && GetProcAddress(module, "_crt_atexit")
        && !GetProcAddress(module, "printf") && !GetProcAddress(module, "fprintf")
        && !GetProcAddress(module, "sprintf") && !GetProcAddress(module, "snprintf")
        && !GetProcAddress(module, "sscanf") && !GetProcAddress(module, "atexit")
        && !GetProcAddress(module, "_onexit");
}

EXPORT int crt_options(unsigned mode) {
    char text[4];
    return __stdio_common_vsprintf(mode == 0 ? 0x100000000ULL : 2,
        text, sizeof(text), "%u", mode == 1 ? (void *)(word)1 : 0, 0);
}

EXPORT unsigned crt_truncation(unsigned capacity) {
    if (capacity > 8) return 0;
    unsigned char text[9];
    for (unsigned i = 0; i < sizeof(text); i++) text[i] = 0xa5;
    unsigned ok = snprintf((char *)text, capacity, "%s", "Hello") == 5;
    unsigned count = capacity == 0 ? 0 : capacity > 5 ? 5 : capacity - 1;
    for (unsigned i = 0; i < count; i++) ok &= text[i] == (unsigned char)"Hello"[i];
    if (capacity) ok &= text[count] == 0;
    for (unsigned i = count + (capacity != 0); i < sizeof(text); i++) ok &= text[i] == 0xa5;
    return ok;
}
#endif

static int variadic(char *output, const char *format, ...) {
    __builtin_va_list args;
    __builtin_va_start(args, format);
    int count = vsprintf(output, format, args);
    __builtin_va_end(args);
    return count;
}

EXPORT unsigned crt_memory(unsigned size) {
    if (size > 257) return 0;
    unsigned char *a = malloc(size + 2), *b = calloc(size + 2, 1);
    if (!a || !b) return 0;
    unsigned ok = 1;
    for (unsigned i = 0; i < size + 2; i++) { ok &= b[i] == 0; a[i] = (unsigned char)(i * 13 + 7); }
    ok &= memcpy(b, a, size + 2) == b && memcmp(a, b, size + 2) == 0;
    ok &= memmove(b + 1, b, size) == b + 1;
    for (unsigned i = 0; i < size; i++) ok &= b[i + 1] == a[i];
    ok &= memset(b, 0xa5, size) == b;
    if (size) ok &= memchr(b, 0xa5, size) == b;
    free(a); free(b); free(0);
    return ok;
}

EXPORT int crt_strings(void) {
    char text[32];
    int ok = strcpy(text, "Hello") == text && strlen(text) == 5 && strnlen(text, 3) == 3;
    ok &= strcmp(text, "Hello") == 0 && strncmp(text, "Hellp", 4) == 0 && strcmp(text, "Hellp") < 0;
    ok &= strchr(text, 'l') == text + 2 && strchr(text, 0) == text + 5;
    ok &= strcspn(text, "lo") == 2;
    ok &= strncpy(text, "A", 4) == text && text[0] == 'A' && text[1] == 0 && text[3] == 0;
    ok &= atoi(" -37x") == -37;
    ok &= toupper('z') == 'Z' && tolower('A') == 'a';
    long number = 0; unsigned marker = 0;
    ok &= sscanf("-27 123", "%ld %u", &number, &marker) == 2 && number == -27 && marker == 123;
    return ok;
}

EXPORT int crt_format(void) {
    char text[64];
    int ok = sprintf(text, "%ld:%u:%s", -2147483647L - 1, 37u, "OK") == 17 && strcmp(text, "-2147483648:37:OK") == 0;
    ok &= variadic(text, "%d %x", -37, 0xabcdef) == 10 && strcmp(text, "-37 abcdef") == 0;
#ifdef UCRT
    ok &= snprintf(text, 4, "%s", "Hello") == 5 && strcmp(text, "Hel") == 0;
    ok &= snprintf(0, 0, "%u", 123u) == 3;
    ok &= fprintf(__acrt_iob_func(1), "stdout:%d\n", 37) == 10;
    ok &= fflush(__acrt_iob_func(1)) == 0;
    ok &= fprintf(__acrt_iob_func(2), "stderr:%s\n", "OK") == 10;
    ok &= fflush(__acrt_iob_func(2)) == 0;
#endif
    return ok;
}

EXPORT int crt_file(void) {
    void *file = fopen("crt.bin", "wb");
    if (!file) return 0;
    int ok = fputs("A\n", file) >= 0 && fwrite("B\0C", 1, 3, file) == 3 && fflush(file) == 0 && fclose(file) == 0;
    file = fopen("crt.bin", "rb");
    if (!file) return 0;
    char bytes[8];
    ok &= fgets(bytes, 8, file) == bytes && bytes[0] == 'A' && bytes[1] == '\n' && bytes[2] == 0;
    ok &= fread(bytes, 2, 2, file) == 1 && bytes[0] == 'B' && bytes[1] == 0 && bytes[2] == 'C';
    ok &= feof(file) != 0 && ferror(file) == 0 && fclose(file) == 0;
    return ok;
}

EXPORT int crt_buffer_full(void) {
    char text[513];
    for (unsigned i = 0; i < sizeof(text) - 1; i++) text[i] = 'X';
    text[sizeof(text) - 1] = 0;
    return printf("%s", text) == (int)sizeof(text) - 1;
}

EXPORT word unsupported_crt(unsigned mode) {
    if (mode == 0) return (word)fopen("crt.bin", "w");
    return rand();
}

EXPORT void entry(void) {
#ifdef UCRT
    printf("exports:%u\n", crt_exports());
    for (unsigned capacity = 0; capacity <= 8; capacity++) printf("truncate:%u %u\n", capacity, crt_truncation(capacity));
#endif
    for (unsigned size = 0; size < 257; size += 1 + size / 8) printf("%u %u\n", size, crt_memory(size));
    int strings = crt_strings(), format = crt_format(), file = crt_file();
    printf("%d %d %d\n", strings, format, file);
    puts("puts"); putchar('!'); putchar('\n');
    ExitProcess(37);
}

#ifdef UCRT
EXPORT int crt_buffering(void) {
    void *output = __acrt_iob_func(1);
    int ok = setvbuf(output, 0, 0, 0) == 0;
    ok &= fprintf(output, "unbuffered\n") == 11;
    return ok;
}
#endif
