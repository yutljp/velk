typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned long long u64;
typedef __UINTPTR_TYPE__ word;
typedef void *handle;
#define API __declspec(dllimport)
#define CALL __stdcall
#define EXPORT __declspec(dllexport)
API u32 CALL GetCurrentProcessId(void);
API u32 CALL GetCurrentThreadId(void);
API handle CALL GetCurrentProcess(void);
API handle CALL GetCurrentThread(void);
API void CALL ExitProcess(u32);
API u32 CALL GetLastError(void);
API void CALL SetLastError(u32);
API void CALL Sleep(u32);
API u32 CALL GetTickCount(void);
API u64 CALL GetTickCount64(void);
API int CALL QueryPerformanceCounter(u64 *);
API int CALL QueryPerformanceFrequency(u64 *);
API void CALL GetSystemTimeAsFileTime(u64 *);
API int CALL IsDebuggerPresent(void);
API int CALL CheckRemoteDebuggerPresent(handle, int *);
API handle CALL GetModuleHandleA(const char *);
API handle CALL GetModuleHandleW(const u16 *);
API handle CALL LoadLibraryA(const char *);
API handle CALL LoadLibraryW(const u16 *);
API void *CALL GetProcAddress(handle, const char *);
API const char *CALL GetCommandLineA(void);
API const u16 *CALL GetCommandLineW(void);
API u16 *CALL GetEnvironmentStringsW(void);
API int CALL FreeEnvironmentStringsW(u16 *);
API u32 CALL TlsAlloc(void);
API int CALL TlsFree(u32);
API void *CALL TlsGetValue(u32);
API int CALL TlsSetValue(u32, void *);
API int printf(const char *, ...);

static __inline __attribute__((always_inline)) word teb(void) {
    word value;
#if defined(__x86_64__)
    __asm__("movq %%gs:0x30, %0" : "=r"(value));
#else
    __asm__("movl %%fs:0x18, %0" : "=r"(value));
#endif
    return value;
}
static word load_pointer(word base, u32 offset) { return *(word *)(base + offset); }
static word peb(void) { return load_pointer(teb(), 12 * sizeof(word)); }
static int text_equal(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}
static int wide_equal(const u16 *a, const u16 *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}
static int wide_name(const u16 *a, const char *b) {
    while (*a && *b) {
        u16 c = *a++;
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c != (unsigned char)*b++) return 0;
    }
    return *a == 0 && *b == 0;
}
static word find_module(const char *name) {
    word ldr = load_pointer(peb(), 3 * sizeof(word));
    word head = ldr + (sizeof(word) == 8 ? 0x20 : 0x14);
    word link = *(word *)head;
    for (u32 count = 0; link != head && count < 64; count++, link = *(word *)link) {
        word entry = link - 2 * sizeof(word);
        const u16 *base_name = (const u16 *)load_pointer(entry, sizeof(word) == 8 ? 0x60 : 0x30);
        if (wide_name(base_name, name)) return load_pointer(entry, 6 * sizeof(word));
    }
    return 0;
}
static void *find_export(word base, const char *name, u16 *ordinal) {
    u32 pe = *(u32 *)(base + 0x3c);
    u32 rva = *(u32 *)(base + pe + (sizeof(word) == 8 ? 0x88 : 0x78));
    u32 directory_size = *(u32 *)(base + pe + (sizeof(word) == 8 ? 0x8c : 0x7c));
    word directory = base + rva;
    u32 count = *(u32 *)(directory + 24);
    u32 *functions = (u32 *)(base + *(u32 *)(directory + 28));
    u32 *names = (u32 *)(base + *(u32 *)(directory + 32));
    u16 *ordinals = (u16 *)(base + *(u32 *)(directory + 36));
    for (u32 index = 0; index < count; index++) {
        if (text_equal((const char *)(base + names[index]), name)) {
            *ordinal = (u16)(*(u32 *)(directory + 16) + ordinals[index]);
            if (functions[ordinals[index]] >= rva && functions[ordinals[index]] < rva + directory_size)
                return GetProcAddress((handle)base, name);
            return (void *)(base + functions[ordinals[index]]);
        }
    }
    return 0;
}

__declspec(thread) unsigned tls_value = 7;
unsigned _tls_index;
#if !defined(__x86_64__)
__asm__(".globl __tls_array\n.set __tls_array, 0x2c");
#endif
#pragma section(".tls", read, write)
#pragma section(".tls$ZZZ", read, write)
__declspec(allocate(".tls")) unsigned char tls_start;
__declspec(allocate(".tls$ZZZ")) unsigned char tls_end;
static unsigned callback_count;
static unsigned callback_arguments;
static unsigned callback_alignment;
static void CALL tls_callback(handle module, u32 reason, void *reserved) {
    callback_count++;
    callback_alignment = ((word)__builtin_frame_address(0) & (sizeof(word) == 8 ? 15 : 3)) == 0;
    callback_arguments = module == GetModuleHandleA(0) && reason == 1 && reserved == 0;
    tls_value += 5;
}
#pragma section(".CRT$XLB", read)
__declspec(allocate(".CRT$XLB")) void (CALL *const tls_callbacks[])(handle, u32, void *) = { tls_callback, 0 };
struct tls_directory { word start, end, index, callbacks; u32 zero, flags; };
const struct tls_directory _tls_used = {
    (word)&tls_start, (word)&tls_end, (word)&_tls_index, (word)tls_callbacks, 16, 0x500000
};

EXPORT unsigned process_state(u32 error) {
    int remote = -1;
    SetLastError(error);
    u32 stored = *(u32 *)(teb() + (sizeof(word) == 8 ? 0x68 : 0x34));
    unsigned flags = *(u32 *)(peb() + (sizeof(word) == 8 ? 0xbc : 0x68));
    unsigned result = GetLastError() == error && stored == error;
    result &= *(unsigned char *)(peb() + 2) == 0 && (flags & 0x70) == 0;
    result &= !IsDebuggerPresent();
    result &= CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote == 0;
    result &= (word)GetCurrentProcess() == (word)-1 && (word)GetCurrentThread() == (word)-2;
    result &= load_pointer(teb(), 8 * sizeof(word)) == GetCurrentProcessId();
    result &= load_pointer(teb(), 9 * sizeof(word)) == GetCurrentThreadId();
    return result;
}

EXPORT unsigned resolve_exports(void) {
    static const u16 kernelbase[] = { 'K','E','R','N','E','L','B','A','S','E','.','D','L','L',0 };
    handle module = GetModuleHandleA("KeRnEl32");
    unsigned result = module != 0 && (word)module == find_module("kernel32.dll");
    result &= find_module("ntdll.dll") != 0 && find_module("kernelbase.dll") != 0;
    result &= GetModuleHandleW(kernelbase) == LoadLibraryA("kernelbase");
    result &= GetModuleHandleW(kernelbase) == LoadLibraryW(kernelbase);
    u16 ordinal;
    void *walked = find_export((word)module, "GetCurrentProcessId", &ordinal);
    u32 (CALL *process_id)(void) = (u32 (CALL *)(void))GetProcAddress(module, "GetCurrentProcessId");
    result &= walked != 0 && process_id != 0;
    result &= ((u32 (CALL *)(void))walked)() == GetCurrentProcessId();
    result &= process_id() == GetCurrentProcessId();
    result &= ((u32 (CALL *)(void))GetProcAddress(module, (const char *)(word)ordinal))() == GetCurrentProcessId();
    void (CALL *set_error)(u32) = (void (CALL *)(u32))GetProcAddress(module, "SetLastError");
    set_error(1234);
    result &= GetLastError() == 1234;
    result &= GetProcAddress(GetModuleHandleA(0), "process_state") == (void *)process_state;
    SetLastError(0);
    result &= GetProcAddress(module, "FunctionThatDoesNotExist") == 0 && GetLastError() == 127;
    result &= GetModuleHandleA("module_that_does_not_exist.dll") == 0 && GetLastError() == 126;
    result &= GetModuleHandleA("C:\\missing\\kernel32.dll") == 0 && GetLastError() == 126;
    return result;
}

EXPORT unsigned process_parameters(void) {
    word parameters = load_pointer(peb(), 4 * sizeof(word));
    u32 image = sizeof(word) == 8 ? 0x60 : 0x38;
    const u16 *path = (const u16 *)load_pointer(parameters, image + sizeof(word));
    const u16 *command = (const u16 *)load_pointer(parameters, image + 3 * sizeof(word));
    u16 *environment = GetEnvironmentStringsW();
    unsigned result = path[0] != 0 && wide_equal(command, GetCommandLineW());
    result &= GetCommandLineA()[0] != 0 && environment != 0;
    result &= FreeEnvironmentStringsW(environment) != 0;
    return result;
}

EXPORT unsigned thread_storage(word value) {
    unsigned result = callback_count == 1 && tls_value == 12;
    u32 index = TlsAlloc();
    result &= index != (u32)-1 && TlsGetValue(index) == 0;
    result &= TlsSetValue(index, (void *)value) != 0;
    SetLastError(73);
    result &= (word)TlsGetValue(index) == value && GetLastError() == 0;
    result &= load_pointer(teb(), (sizeof(word) == 8 ? 0x1480 : 0xe10) + index * sizeof(word)) == value;
    result &= TlsFree(index) != 0;
    return result;
}

EXPORT unsigned process_clocks(void) {
    u64 counter, frequency, after, filetime;
    unsigned result = QueryPerformanceFrequency(&frequency) && frequency != 0;
    result &= QueryPerformanceCounter(&counter);
    u64 ticks = GetTickCount64();
    Sleep(2);
    result &= QueryPerformanceCounter(&after) && after >= counter;
    result &= GetTickCount64() >= ticks;
    u32 ticks32 = GetTickCount();
    result &= (u32)GetTickCount64() - ticks32 < 1000;
    GetSystemTimeAsFileTime(&filetime);
    result &= filetime >= 116444736000000000ULL;
    return result;
}

EXPORT unsigned callback_state(void) { return callback_count == 1 && callback_arguments && callback_alignment && tls_value == 12; }
EXPORT void finish(u32 code) { ExitProcess(code); }
EXPORT void sleep_forever(void) { Sleep((u32)-1); }
EXPORT void counter_to(u64 *pointer) { QueryPerformanceCounter(pointer); }
EXPORT unsigned copy_parameters(u16 *buffer) {
    const u16 *text = GetCommandLineW();
    unsigned count = 0;
    do { buffer[count] = text[count]; } while (text[count++]);
    return count - 1;
}
EXPORT unsigned copy_image_path(u16 *buffer) {
    word parameters = load_pointer(peb(), 4 * sizeof(word));
    const u16 *text = (const u16 *)load_pointer(parameters, (sizeof(word) == 8 ? 0x60 : 0x38) + sizeof(word));
    unsigned count = 0;
    do { buffer[count] = text[count]; } while (text[count++]);
    return count - 1;
}
EXPORT unsigned copy_module_name(u16 *buffer) {
    word ldr = load_pointer(peb(), 3 * sizeof(word));
    word link = load_pointer(ldr, sizeof(word) == 8 ? 0x20 : 0x14);
    word entry = link - 2 * sizeof(word);
    const u16 *text = (const u16 *)load_pointer(entry, sizeof(word) == 8 ? 0x60 : 0x30);
    unsigned count = 0;
    do { buffer[count] = text[count]; } while (text[count++]);
    return count - 1;
}
EXPORT u64 tick_after_sleep(u32 milliseconds) { Sleep(milliseconds); return GetTickCount64(); }
EXPORT u32 tick_high(void) { Sleep(0xfffffffe); Sleep(0xfffffffe); return (u32)(GetTickCount64() >> 32); }
EXPORT u32 tick_low(void) { Sleep(0xfffffffe); Sleep(0xfffffffe); return GetTickCount(); }
EXPORT unsigned current_process_id(void) { return GetCurrentProcessId(); }
EXPORT unsigned patch_debugger_flag(u32 value) {
    *(unsigned char *)(peb() + 2) = (unsigned char)value;
    return IsDebuggerPresent();
}
EXPORT __attribute__((naked)) unsigned tail_process_id(void) {
#if defined(__x86_64__)
    __asm__("movq __imp_GetCurrentProcessId(%rip), %rax\njmp *%rax");
#else
    __asm__("movl \"__imp__GetCurrentProcessId@0\", %eax\njmp *%eax");
#endif
}
EXPORT unsigned replacement_process_id(void) { return 12345; }
EXPORT void write_export(void) {
    volatile unsigned char *address = GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetCurrentProcessId");
    *address = 0;
}
EXPORT void copy_environment(u16 *buffer) {
    const u16 *source = (const u16 *)load_pointer(load_pointer(peb(), 4 * sizeof(word)), sizeof(word) == 8 ? 0x80 : 0x48);
    unsigned count = 0;
    do { buffer[count] = source[count]; count++; } while (source[count - 1] || source[count]);
    buffer[count] = 0;
}
EXPORT void entry(void) {
    printf("%u %u %u %u %u\n", process_state(0x12345678), resolve_exports(), process_parameters(), thread_storage(0x87654321), process_clocks());
    ExitProcess(37);
}
