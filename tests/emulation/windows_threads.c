typedef __UINTPTR_TYPE__ word;
#define API __declspec(dllimport)
#define EXPORT __declspec(dllexport)
API void *__stdcall CreateThread(void *, word, unsigned (__stdcall *)(void *), void *, unsigned, unsigned *);
API unsigned __stdcall WaitForSingleObject(void *, unsigned);
API int __stdcall GetExitCodeThread(void *, unsigned *);
API void __stdcall ExitThread(unsigned);
API void __stdcall ExitProcess(unsigned);
API int __stdcall CloseHandle(void *);
API unsigned __stdcall GetCurrentThreadId(void);
API unsigned __stdcall GetLastError(void);
API void __stdcall SetLastError(unsigned);
API unsigned __stdcall TlsAlloc(void);
API int __stdcall TlsSetValue(unsigned, void *);
API void *__stdcall TlsGetValue(unsigned);
API int __stdcall TlsFree(unsigned);
API int printf(const char *, ...);

__declspec(thread) unsigned tls_value = 7;
unsigned _tls_index;
#if !defined(__x86_64__)
__asm__(".globl __tls_array\n.set __tls_array, 0x2c");
#endif
#pragma section(".tls", read, write)
#pragma section(".tls$ZZZ", read, write)
#pragma section(".CRT$XLB", read)
__declspec(allocate(".tls")) unsigned char tls_start;
__declspec(allocate(".tls$ZZZ")) unsigned char tls_end;
static unsigned slot;
static unsigned creator;
static unsigned worker_id;
EXPORT unsigned events[4];
EXPORT word events_address(void) { return (word)events; }
static void __stdcall callback(void *module, unsigned reason, void *reserved) {
    (void)module;
    if (reason < 4) events[reason]++;
    if (reason == 1 || reason == 2) tls_value += 5;
    if (reason == 2) {
        worker_id = GetCurrentThreadId();
        if (reserved || tls_value != 12 || TlsGetValue(slot)) events[2] += 100;
    }
    if (reason == 3 && (reserved || tls_value != 99 || TlsGetValue(slot) != (void *)37)) events[3] += 100;
}
__declspec(allocate(".CRT$XLB")) void (__stdcall *const callbacks[])(void *, unsigned, void *) = {callback, 0};
struct tls_directory { word start, end, index, callbacks; unsigned zero, flags; };
const struct tls_directory _tls_used = {
    (word)&tls_start, (word)&tls_end, (word)&_tls_index, (word)callbacks, 16, 0x500000
};
static unsigned __stdcall worker(void *parameter) {
    unsigned ok = tls_value == 12 && GetCurrentThreadId() != creator && GetCurrentThreadId() == worker_id;
    ok &= GetLastError() == 0 && TlsGetValue(slot) == 0;
    SetLastError(71); TlsSetValue(slot, (void *)37); tls_value = 99;
    if (parameter) ExitThread(ok ? 37 : 99);
    return ok ? 37 : 99;
}
EXPORT unsigned thread_storage(unsigned mode) {
    creator = GetCurrentThreadId();
    slot = TlsAlloc(); TlsSetValue(slot, (void *)19); SetLastError(53);
    unsigned id, code;
    void *thread = CreateThread(0, 0, worker, (void *)(word)mode, 0, &id);
    if (!thread) return 0;
    if (WaitForSingleObject(thread, ~0u) != 0) return 0;
    unsigned ok = GetExitCodeThread(thread, &code) && code == 37;
    ok &= id == worker_id && GetCurrentThreadId() == creator;
    ok &= GetLastError() == 53 && tls_value == 12 && TlsGetValue(slot) == (void *)19;
    ok &= events[2] == 1 && events[3] == 1;
    ok &= CloseHandle(thread) && TlsFree(slot);
    return ok;
}
EXPORT void entry(void) {
    printf("%u\n", thread_storage(0));
    events[2] = events[3] = 0;
    printf("%u\n", thread_storage(1));
    ExitProcess(37);
}
EXPORT unsigned thread_boundary(unsigned mode) {
    unsigned code = 0;
    if (mode == 0) return WaitForSingleObject((void *)1, 0) == ~0u && GetLastError() == 6;
    if (mode == 1) return GetExitCodeThread((void *)1, &code) == 0 && GetLastError() == 6;
    if (mode == 2) { ExitThread(37); return 0; }
    unsigned id;
    void *thread = CreateThread(0, 0, worker, 0, 0, &id);
    if (mode == 3) return WaitForSingleObject(thread, 0) == 258 && GetExitCodeThread(thread, &code) && code == 259;
    if (mode == 4) return WaitForSingleObject(thread, 1);
    if (mode == 5) return CloseHandle(thread);
    return (unsigned)(word)CreateThread(0, 0, worker, 0, 4, &id);
}
