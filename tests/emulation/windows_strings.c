typedef unsigned int u32;
typedef unsigned short u16;
typedef __UINTPTR_TYPE__ word;
#define API __declspec(dllimport)
#define CALL __stdcall
#define EXPORT __declspec(dllexport)
API int CALL MultiByteToWideChar(u32, u32, const char *, int, u16 *, int);
API int CALL WideCharToMultiByte(u32, u32, const u16 *, int, char *, int, const char *, int *);
API int CALL lstrlenA(const char *);
API int CALL lstrlenW(const u16 *);
API u32 CALL GetLastError(void);
API void CALL SetLastError(u32);
API void CALL ExitProcess(u32);
API int printf(const char *, ...);
API int fflush(void *);
API void *CALL GetModuleHandleA(const char *);
API void *CALL GetProcAddress(void *, const char *);

static const char *inputs[] = {"", "ASCII", "A\0B", "\xc3\xa9", "\xe6\x97\xa5\xe6\x9c\xac", "\xf0\x9f\x98\x80", "\xff", "\xe2\x82", "\xc0\xaf", "\xed\xa0\x80"};
static const u16 wide_inputs[][8] = {{0}, {'A','S','C','I','I',0}, {'A',0,'B',0}, {0xe9,0}, {0x65e5,0x672c,0}, {0xd83d,0xde00,0}, {0xdc00,0}, {0xd800,'A',0}, {0xd800,0xd800,0}};

EXPORT int string_lengths(void) {
    const u16 raw[] = {0xd800, 'A', 0};
    return lstrlenA(0) == 0 && lstrlenW(0) == 0 && lstrlenA(inputs[5]) == 4 &&
        lstrlenW(wide_inputs[5]) == 2 && lstrlenW(raw) == 2;
}

EXPORT int conversion(unsigned mode, unsigned index, int length, int capacity, unsigned flags) {
    u16 wide[16];
    char bytes[32];
    for (unsigned i = 0; i < 16; i++) wide[i] = 0x5555;
    for (unsigned i = 0; i < 32; i++) bytes[i] = 0x55;
    SetLastError(73);
    int count;
    if (mode == 0) count = MultiByteToWideChar(65001, flags, inputs[index % 10], length, wide + 1, capacity);
    else count = WideCharToMultiByte(65001, flags, wide_inputs[index % 9], length, bytes + 1, capacity, 0, 0);
    u32 error = GetLastError();
    printf("%u %u %d %d %u: %d %u", mode, index, length, capacity, flags, count, error);
    if (count > 0 && capacity > 0) {
        if (mode == 0) for (unsigned i = 0; i < 16; i++) printf(" %x", (unsigned)wide[i]);
        else for (unsigned i = 0; i < 32; i++) printf(" %x", (unsigned char)bytes[i]);
    }
    printf("\n");
    fflush(0);
    return count;
}

EXPORT int conversion_boundaries(void) {
    u16 wide[8];
    char bytes[8];
    int used = 99;
    int ok = string_lengths();
    ok &= MultiByteToWideChar(0, 0, "A", -1, wide, 8) == 2 && wide[0] == 'A' && wide[1] == 0;
    ok &= WideCharToMultiByte(0, 0, wide, -1, bytes, 8, "?", &used) == 2 && used == 0 && bytes[0] == 'A' && bytes[1] == 0;
    ok &= MultiByteToWideChar(65001, 0, "A", -1, 0, 0) == 2;
    ok &= WideCharToMultiByte(65001, 0, wide, -1, 0, 0, 0, 0) == 2;
    ok &= !MultiByteToWideChar(65001, 0, 0, -1, wide, 8) && GetLastError() == 87;
    ok &= !MultiByteToWideChar(65001, 0, "A", 0, wide, 8) && GetLastError() == 87;
    ok &= !MultiByteToWideChar(65001, 0, "A", -1, wide, -1) && GetLastError() == 87;
    return ok;
}

EXPORT int documented_parameter_checks(void) {
    u16 wide[8] = {'A', 0};
    char bytes[8] = {0};
    int used = 99;
    // Windows documents these invalid parameters as ERROR_INVALID_PARAMETER.
    int ok = !MultiByteToWideChar(65001, 0, "A", -2, wide, 8) && GetLastError() == 87;
    ok &= !MultiByteToWideChar(65001, 0, (char *)wide, -1, wide, 8) && GetLastError() == 87;
    ok &= !WideCharToMultiByte(65001, 0, wide, -1, bytes, 8, "?", 0) && GetLastError() == 87;
    ok &= !WideCharToMultiByte(65001, 0, wide, -1, bytes, 8, 0, &used) && GetLastError() == 87;
    return ok;
}

EXPORT int convert_buffer(unsigned code_page, unsigned flags, const char *input, int length, u16 *output, int capacity) {
    return MultiByteToWideChar(code_page, flags, input, length, output, capacity);
}

EXPORT int dynamic_conversion(void) {
    int (CALL *convert)(u32, u32, const char *, int, u16 *, int) = GetProcAddress(GetModuleHandleA("kernelbase"), "MultiByteToWideChar");
    u16 output[4];
    return convert && convert(65001, 8, "\xf0\x9f\x98\x80", -1, output, 4) == 3 && output[0] == 0xd83d && output[1] == 0xde00 && output[2] == 0;
}

EXPORT void entry(void) {
    printf("%d %d %d\n", string_lengths(), conversion_boundaries(), dynamic_conversion());
    for (unsigned mode = 0; mode < 2; mode++)
        for (unsigned index = 0; index < (mode == 0 ? 10u : 9u); index++)
            for (int length = -1; length <= 1; length++)
                for (int capacity = 0; capacity <= 8; capacity += 2)
                    for (unsigned flag = 0; flag < 3; flag++) {
                        if (length == 0 && flag != 0) continue;
                        if (flag == 2 && (length != -1 || capacity != 8)) continue;
                        if (index >= 6 && capacity != 0 && capacity != 8) continue;
                        if (mode == 0 && flag == 2) continue;
                        conversion(mode, index, length, capacity, flag == 0 ? 0 : flag == 1 ? (mode == 0 ? 8 : 0x80) : 1);
                    }
    ExitProcess(37);
}
