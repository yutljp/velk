typedef __UINTPTR_TYPE__ word;
typedef __SIZE_TYPE__ size_t;
#define API __declspec(dllimport)
#define EXPORT __declspec(dllexport)
#ifdef UCRT
#include "windows_ucrt.h"
#else
API int printf(const char *, ...);
API int sprintf(char *, const char *, ...);
API int atexit(void (*)(void));
API void * _onexit(void *);
#endif
API int puts(const char *);
API int putchar(int);
API void exit(int);
API void *fopen(const char *, const char *);
API int fputs(const char *, void *);
API void __stdcall ExitProcess(unsigned);
API void *__stdcall CreateFileA(const char *, unsigned, unsigned, void *, unsigned, unsigned, void *);
API int __stdcall WriteFile(void *, const void *, unsigned, unsigned *, void *);
API int __stdcall CloseHandle(void *);

static void *file;
static void *direct;
EXPORT unsigned events;
EXPORT word events_address(void) { return (word)&events; }
static void first(void) { events = events * 10 + 1; printf("first\n"); fputs("first\n", file); }
static int second(void) { events = events * 10 + 2; puts("second"); fputs("second\n", file); return 0; }

static void __stdcall callback(void *module, unsigned reason, void *reserved) {
    (void)module; (void)reserved;
    if (reason != 0) return;
    events = events * 10 + 3;
    printf("hidden printf\n"); puts("hidden puts"); putchar('!');
    char buffer[16];
    int count = sprintf(buffer, "direct:%u\n", events);
    unsigned written;
    WriteFile(direct, buffer, (unsigned)count, &written, 0);
    CloseHandle(direct);
}
unsigned _tls_index;
#pragma section(".tls", read, write)
#pragma section(".tls$ZZZ", read, write)
#pragma section(".CRT$XLB", read)
__declspec(allocate(".tls")) unsigned char tls_start;
__declspec(allocate(".tls$ZZZ")) unsigned char tls_end;
__declspec(allocate(".CRT$XLB")) void (__stdcall *const callbacks[])(void *, unsigned, void *) = {callback, 0};
struct tls_directory { word start, end, index, callbacks; unsigned zero, flags; };
const struct tls_directory _tls_used = {
    (word)&tls_start, (word)&tls_end, (word)&_tls_index, (word)callbacks, 0, 0
};

EXPORT void finish(unsigned mode) {
    file = fopen("exit.bin", "wb");
    direct = CreateFileA("detach.bin", 0x40000000, 0, 0, 2, 0x80, 0);
    fputs("body\n", file);
    printf("body\n");
    atexit(first); _onexit((void *)second);
    if (mode == 1) ExitProcess(37);
    exit(37);
}
EXPORT void entry(void) { finish(0); }
