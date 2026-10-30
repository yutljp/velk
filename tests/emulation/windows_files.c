typedef unsigned int u32;
typedef __SIZE_TYPE__ size_t;
typedef unsigned short u16;
typedef __UINTPTR_TYPE__ word;
typedef void *handle;
#define API __declspec(dllimport)
#define CALL __stdcall
#define EXPORT __declspec(dllexport)
#define INVALID ((handle)(word)-1)
API handle CALL CreateFileA(const char *, u32, u32, void *, u32, u32, handle);
API handle CALL CreateFileW(const u16 *, u32, u32, void *, u32, u32, handle);
API handle CALL GetStdHandle(u32);
API int CALL CloseHandle(handle);
API int CALL WriteFile(handle, const void *, u32, u32 *, void *);
API int CALL ReadFile(handle, void *, u32, u32 *, void *);
API int CALL WriteConsoleA(handle, const void *, u32, u32 *, void *);
API int CALL WriteConsoleW(handle, const void *, u32, u32 *, void *);
API u32 CALL GetLastError(void);
API void CALL SetLastError(u32);
API void CALL ExitProcess(u32);
API int printf(const char *, ...);
API void *fopen(const char *, const char *);
API int fclose(void *);
API size_t fread(void *, size_t, size_t, void *);

EXPORT u32 file_results[3];
EXPORT word file_address(void) { return (word)file_results; }

EXPORT int file_roundtrip(unsigned length) {
    unsigned char input[256], output[260];
    if (length > 256) return 0;
    for (unsigned i = 0; i < 256; i++) input[i] = (unsigned char)(i * 17 + 3);
    for (unsigned i = 0; i < 260; i++) output[i] = 0x55;
    handle file = CreateFileW(L"record.bin", 0xc0000000, 3, 0, 2, 0x80, 0);
    if (file == INVALID) return 0;
    u32 count = 99;
    int ok = WriteFile(file, input, length, &count, 0) && count == length;
    ok &= CloseHandle(file) != 0;
    file = CreateFileA("RECORD.BIN", 0x80000000, 1, 0, 3, 0, 0);
    if (file == INVALID) return 0;
    ok &= ReadFile(file, output + 1, length + 2, &count, 0) && count == length;
    u32 checksum = 0;
    for (unsigned i = 0; i < length; i++) {
        ok &= output[i + 1] == input[i];
        checksum = checksum * 31 + output[i + 1];
    }
    ok &= output[0] == 0x55 && output[length + 1] == 0x55;
    count = 99;
    ok &= ReadFile(file, output, 1, &count, 0) && count == 0;
    ok &= CloseHandle(file) != 0;
    file_results[0] = ok;
    file_results[1] = count;
    file_results[2] = checksum;
    return ok;
}

EXPORT int file_boundaries(void) {
    u32 count = 99;
    char byte = 'X';
    handle file = CreateFileA("boundary.bin", 0xc0000000, 0, 0, 2, 0x80, 0);
    if (file == INVALID) return 0;
    int ok = CreateFileA("boundary.bin", 0x80000000, 3, 0, 3, 0, 0) == INVALID && GetLastError() == 32;
    ok &= CloseHandle(file) != 0;
    ok &= !CloseHandle(file) && GetLastError() == 6;
    ok &= CreateFileA("boundary.bin", 0xc0000000, 3, 0, 1, 0, 0) == INVALID && GetLastError() == 80;
    file = CreateFileA("boundary.bin", 0xc0000000, 3, 0, 4, 0, 0);
    ok &= file != INVALID && GetLastError() == 183;
    ok &= WriteFile(file, &byte, 0, &count, 0) && count == 0;
    ok &= CloseHandle(file) != 0;
    file = CreateFileA("boundary.bin", 0x80000000, 3, 0, 3, 0, 0);
    ok &= !WriteFile(file, &byte, 1, &count, 0) && count == 0 && GetLastError() == 5;
    ok &= !WriteConsoleA(file, &byte, 1, &count, 0) && GetLastError() == 6;
    ok &= CloseHandle(file) != 0;
    ok &= !ReadFile(INVALID, &byte, 1, &count, 0) && count == 0 && GetLastError() == 6;
    ok &= CreateFileA("missing-input.bin", 0x80000000, 3, 0, 3, 0, 0) == INVALID && GetLastError() == 2;
    return ok;
}

EXPORT int read_supplied(void) {
    char bytes[8];
    u32 count;
    handle file = CreateFileA("input.bin", 0x80000000, 3, 0, 3, 0, 0);
    if (file == INVALID) return 0;
    int ok = ReadFile(file, bytes, 8, &count, 0) && count == 3 && bytes[0] == 'A' && bytes[1] == 0 && bytes[2] == 'B';
    ok &= CloseHandle(file) != 0;
    ok &= ReadFile(GetStdHandle((u32)-10), bytes, 8, &count, 0) && count == 2 && bytes[0] == 'O' && bytes[1] == 'K';
    return ok;
}

EXPORT int console_output(void) {
    u32 count;
    const u16 wide[] = {0x65e5,0xd83d,0xde00,0};
    int ok = WriteConsoleA(GetStdHandle((u32)-11), "ASCII", 5, &count, 0) && count == 5;
    ok &= WriteConsoleW(GetStdHandle((u32)-11), wide, 3, &count, 0) && count == 3;
    ok &= WriteFile(GetStdHandle((u32)-12), "error\0\n", 7, &count, 0) && count == 7;
    ok &= GetStdHandle(0) == INVALID && GetLastError() == 87;
    return ok;
}

EXPORT int process_output(void) {
    word thread;
#if defined(__x86_64__)
    __asm__("movq %%gs:0x30, %0" : "=r"(thread));
#else
    __asm__("movl %%fs:0x18, %0" : "=r"(thread));
#endif
    word process = *(word *)(thread + 12 * sizeof(word));
    word parameters = *(word *)(process + 4 * sizeof(word));
    handle output = *(handle *)(parameters + (sizeof(word) == 8 ? 0x28 : 0x1c));
    u32 count;
    return output == GetStdHandle((u32)-11) && WriteFile(output, "peb\n", 4, &count, 0) && count == 4;
}

EXPORT word unsupported_file(unsigned mode) {
    u32 count;
    if (mode == 0) return (word)CreateFileA("record.bin", 0xc0000000, 3, 0, 2, 0x40000080, 0);
    if (mode == 1) return (word)CreateFileA("..\\record.bin", 0xc0000000, 3, 0, 2, 0, 0);
    if (mode == 2) return WriteFile(GetStdHandle((u32)-11), "X", 1, &count, (void *)(word)1);
    if (mode == 3) return WriteFile(GetStdHandle((u32)-11), "X", 1, 0, 0);
    return WriteFile(GetStdHandle((u32)-11), "X", 0xffffffff, &count, 0);
}

EXPORT int process_files(void) {
    handle file = CreateFileA("/proc/self/status", 0x80000000, 3, 0, 3, 0, 0);
    int ok = file == INVALID && GetLastError() == 2;
    file = CreateFileA("/proc/self/maps", 0x40000000, 0, 0, 1, 0, 0);
    if (file == INVALID) return 0;
    u32 count;
    ok &= WriteFile(file, "X", 1, &count, 0) && count == 1 && CloseHandle(file);
    return ok;
}

EXPORT int mixed_files(unsigned mode) {
    u32 count;
    char byte = 0;
    handle file = CreateFileA("shared.bin", 0xc0000000, 3, 0, 2, 0, 0);
    if (file == INVALID) return 0;
    int ok = WriteFile(file, "X", 1, &count, 0) && count == 1 && CloseHandle(file);
    if (mode == 1) file = CreateFileA("shared.bin", 0xc0000000, 3, 0, 3, 0, 0);
    void *stream = fopen("shared.bin", "rb");
    if (!stream) return 0;
    if (mode == 2) file = CreateFileA("shared.bin", 0xc0000000, 3, 0, 3, 0, 0);
    ok &= fread(&byte, 1, 1, stream) == 1 && byte == 'X' && fclose(stream) == 0;
    if (mode == 1 || mode == 2) ok &= CloseHandle(file) != 0;
    return ok;
}

EXPORT void entry(void) {
    for (unsigned length = 0; length <= 256; length += 1 + length / 8) {
        int ok = file_roundtrip(length);
        printf("%u %d %u\n", length, ok, file_results[2]);
    }
    printf("%d\n", file_boundaries());
    printf("%d\n", process_output());
    printf("%d\n", mixed_files(0));
    u32 count;
    WriteFile(GetStdHandle((u32)-11), "output\n", 7, &count, 0);
    ExitProcess(37);
}
