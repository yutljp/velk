typedef unsigned int u32;
typedef unsigned short u16;
typedef __UINTPTR_TYPE__ word;
typedef void *handle;
#define API __declspec(dllimport)
#define CALL __stdcall
#define EXPORT __declspec(dllexport)
API handle CALL GetProcessHeap(void);
API void *CALL HeapAlloc(handle, u32, word);
API void *CALL HeapReAlloc(handle, u32, void *, word);
API int CALL HeapFree(handle, u32, void *);
API void *CALL VirtualAlloc(void *, word, u32, u32);
API int CALL VirtualProtect(void *, word, u32, u32 *);
API int CALL VirtualFree(void *, word, u32);
API u32 CALL GetLastError(void);
API void CALL SetLastError(u32);
API void CALL ExitProcess(u32);
API handle CALL GetModuleHandleA(const char *);
API void *CALL GetProcAddress(handle, const char *);
API int printf(const char *, ...);

EXPORT u32 memory_results[4];
EXPORT word memory_address(void) { return (word)memory_results; }

EXPORT unsigned heap_state(word size) {
    handle heap = GetProcessHeap();
    word thread;
#if defined(__x86_64__)
    __asm__("movq %%gs:0x30, %0" : "=r"(thread));
#else
    __asm__("movl %%fs:0x18, %0" : "=r"(thread));
#endif
    word peb = *(word *)(thread + 12 * sizeof(word));
    unsigned result = heap != 0 && heap == *(handle *)(peb + 6 * sizeof(word));
    unsigned char *p = HeapAlloc(heap, 8, size);
    result &= p != 0 && ((word)p & (sizeof(word) == 8 ? 15 : 7)) == 0;
    if (!p) return 0;
    for (word i = 0; i < size; i++) { result &= p[i] == 0; p[i] = (unsigned char)(i * 13 + 7); }
    void *other = HeapAlloc(heap, 0, 48);
    unsigned char *q = HeapReAlloc(heap, 8, p, size + 33);
    if (!q) return 0;
    for (word i = 0; i < size; i++) result &= q[i] == (unsigned char)(i * 13 + 7);
    for (word i = size; i < size + 33; i++) result &= q[i] == 0;
    q = HeapReAlloc(heap, 0x10, q, size / 2);
    result &= q != 0;
    if (q) for (word i = 0; i < size / 2; i++) result &= q[i] == (unsigned char)(i * 13 + 7);
    result &= HeapFree(heap, 0, q) != 0;
    result &= HeapFree(heap, 0, other) != 0;
    result &= HeapFree(heap, 0, 0) != 0;
    memory_results[0] = result;
    memory_results[1] = (u32)size;
    return result;
}

EXPORT unsigned virtual_state(word size) {
    unsigned char *p = VirtualAlloc(0, 0x3000, 0x2000, 1);
    if (!p) return 0;
    unsigned result = ((word)p & 0xffff) == 0;
    unsigned char *q = VirtualAlloc(p + 0x1001, size, 0x1000, 4);
    result &= q == p + 0x1000;
    if (!q) return 0;
    for (word i = 0; i < size; i++) { result &= q[i] == 0; q[i] = (unsigned char)(i * 17 + 3); }
    result &= VirtualAlloc(q, size, 0x1000, 4) == q;
    for (word i = 0; i < size; i++) result &= q[i] == (unsigned char)(i * 17 + 3);
    u32 previous = 0;
    result &= VirtualProtect(q, size, 2, &previous) != 0 && previous == 4;
    u32 checksum = 0;
    for (word i = 0; i < size; i++) checksum = checksum * 31 + q[i];
    result &= VirtualProtect(q, size, 4, &previous) != 0 && previous == 2;
    result &= VirtualFree(q, size, 0x4000) != 0;
    result &= VirtualFree(q, size, 0x4000) != 0;
    result &= VirtualAlloc(q, size, 0x1000, 4) == q;
    for (word i = 0; i < size; i++) result &= q[i] == 0;
    SetLastError(0);
    result &= !VirtualFree(p, 1, 0x8000) && GetLastError() == 87;
    result &= VirtualFree(p, 0, 0x8000) != 0;
    memory_results[2] = result;
    memory_results[3] = checksum;
    return result;
}

EXPORT unsigned virtual_boundaries(void) {
    unsigned char *p = VirtualAlloc(0, 0x3000, 0x3000, 4);
    if (!p) return 0;
    u32 previous;
    unsigned result = VirtualProtect(p + 0xfff, 2, 2, &previous) && previous == 4;
    result &= VirtualProtect(p + 0x1000, 1, 4, &previous) && previous == 2;
    result &= VirtualProtect(p + 0x2000, 1, 4, &previous) && previous == 4;
    result &= !VirtualProtect(p, 1, 4, 0);
    result &= VirtualProtect(p, 1, 4, &previous) && previous == 2;
    result &= VirtualFree(p, 0, 0x4000) != 0;
    result &= !VirtualProtect(p, 1, 4, &previous);
    result &= VirtualFree(p, 0, 0x8000) != 0;
    unsigned char *fixed = VirtualAlloc((void *)(word)0x50001234, 2, 0x3000, 4);
    result &= fixed == (void *)(word)0x50000000;
    if (fixed) {
        result &= fixed[0] == 0 && fixed[0x1234] == 0;
        result &= !VirtualAlloc(fixed, 1, 0x2000, 4);
        result &= VirtualFree(fixed, 0, 0x8000) != 0;
    }
    return result;
}

EXPORT word heap_oversize(word size) {
    handle heap = GetProcessHeap();
    SetLastError(73);
    void *p = HeapAlloc(heap, 8, size);
    return p == 0 && GetLastError() == 73;
}
EXPORT word heap_reallocation_failure(word size) {
    handle heap = GetProcessHeap();
    unsigned char *p = HeapAlloc(heap, 8, 17);
    if (!p) return 0;
    p[16] = 91;
    SetLastError(73);
    void *q = HeapReAlloc(heap, 0, p, size);
    unsigned result = !q && p[16] == 91 && GetLastError() == 73;
    HeapFree(heap, 0, p);
    return result;
}
EXPORT word virtual_oversize(word size) { return (word)VirtualAlloc(0, size, 0x3000, 4); }
EXPORT word virtual_overflow(word address) { return (word)VirtualAlloc((void *)address, 0x1001, 0x3000, 4); }
EXPORT unsigned virtual_invalid_output(word output) {
    void *p = VirtualAlloc(0, 0x1000, 0x3000, 4);
    return VirtualProtect(p, 1, 2, (u32 *)output);
}
EXPORT unsigned dynamic_heap(void) {
    handle module = GetModuleHandleA("kernelbase.dll");
    handle (CALL *heap)(void) = (handle (CALL *)(void))GetProcAddress(module, "GetProcessHeap");
    void *(CALL *allocate)(handle, u32, word) = (void *(CALL *)(handle, u32, word))GetProcAddress(module, "HeapAlloc");
    int (CALL *release)(handle, u32, void *) = (int (CALL *)(handle, u32, void *))GetProcAddress(module, "HeapFree");
    void *p = allocate(heap(), 8, 32);
    return p != 0 && release(heap(), 0, p);
}
EXPORT unsigned virtual_fault(u32 mode) {
    volatile unsigned char *p = VirtualAlloc(0, 0x2000, mode == 0 ? 0x2000 : 0x3000, 4);
    u32 old;
    if (mode == 1) VirtualProtect((void *)p, 1, 1, &old);
    if (mode == 2 || mode == 5) VirtualProtect((void *)(p + 0x1000), 1, 2, &old);
    if (mode == 3) VirtualFree((void *)p, 1, 0x4000);
    if (mode == 4) VirtualFree((void *)p, 0, 0x8000);
    if (mode == 6) VirtualProtect((void *)p, 1, 0x10, &old);
    if (mode == 7) VirtualProtect((void *)p, 1, 0x20, &old);
    if (mode == 8) VirtualProtect((void *)p, 1, 0x40, &old);
    if (mode == 9) VirtualFree((void *)(p + 1), 0, 0x8000);
    if (mode == 2) p[0x1000] = 7;
    if (mode == 5) *(volatile u16 *)(p + 0xfff) = 7;
    if (mode == 7 || mode == 8) p[0] = 7;
    return p[0];
}
EXPORT void entry(void) {
    for (word size = 0; size < 130; size += 1 + size / 8) {
        unsigned heap = heap_state(size);
        unsigned pages = virtual_state(size + 1);
        printf("%u %u %u %u\n", heap, pages, memory_results[1], memory_results[3]);
    }
    printf("%u %u\n", virtual_boundaries(), dynamic_heap());
    ExitProcess(37);
}
