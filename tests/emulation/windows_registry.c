typedef unsigned int u32;
typedef unsigned short u16;
typedef __UINTPTR_TYPE__ word;
typedef void *handle;
#define API __declspec(dllimport)
#define CALL __stdcall
#define EXPORT __declspec(dllexport)
#define HKCU ((handle)(word)(__INTPTR_TYPE__)(int)0x80000001)
API int CALL RegOpenKeyExA(handle, const char *, u32, u32, handle *);
API int CALL RegOpenKeyExW(handle, const u16 *, u32, u32, handle *);
API int CALL RegQueryValueExA(handle, const char *, u32 *, u32 *, void *, u32 *);
API int CALL RegQueryValueExW(handle, const u16 *, u32 *, u32 *, void *, u32 *);
API int CALL RegCloseKey(handle);
API int CALL RegCreateKeyExW(handle, const u16 *, u32, u16 *, u32, u32, void *, handle *, u32 *);
API int CALL RegSetValueExW(handle, const u16 *, u32, u32, const void *, u32);
API int CALL RegDeleteKeyW(handle, const u16 *);
API void CALL SetLastError(u32);
API u32 CALL GetLastError(void);
API void CALL ExitProcess(u32);
API int printf(const char *, ...);

EXPORT int registry_values(void) {
    handle key;
    SetLastError(73);
    if (RegOpenKeyExA(HKCU, "Software\\VelkEmulationTest", 0, 0x20019, &key)) return 0;
    u32 type = 0, size = 0, number = 0;
    int ok = RegQueryValueExA(key, "number", 0, &type, 0, &size) == 0 && type == 4 && size == 4;
    size = 3;
    ok &= RegQueryValueExA(key, "Number", 0, &type, &number, &size) == 234 && type == 4 && size == 4;
    size = 4;
    ok &= RegQueryValueExW(key, L"Number", 0, &type, &number, &size) == 0 && number == 0x89abcdef && size == 4;
    char text[8];
    size = 8;
    ok &= RegQueryValueExA(key, "Text", 0, &type, text, &size) == 0 && type == 1 && size == 6 && text[0] == 'H' && text[4] == 'o' && text[5] == 0;
    u16 wide[8];
    size = sizeof(wide);
    ok &= RegQueryValueExW(key, 0, 0, &type, wide, &size) == 0 && type == 1 && size == 4 && wide[0] == 0x65e5 && wide[1] == 0;
    type = 0;
    ok &= RegQueryValueExA(key, 0, 0, &type, 0, 0) == 0 && type == 1;
    unsigned char binary[8];
    size = 8;
    ok &= RegQueryValueExW(key, L"Bytes", 0, &type, binary, &size) == 0 && type == 3 && size == 3 && binary[0] == 0 && binary[1] == 0xff && binary[2] == 7;
    ok &= RegQueryValueExA(key, "missing", 0, 0, 0, 0) == 2;
    ok &= RegCloseKey(key) == 0;
    ok &= RegOpenKeyExA(HKCU, 0, 0, 1, &key) == 0 && key == HKCU;
    ok &= RegCloseKey(key) == 0;
    ok &= RegOpenKeyExW(HKCU, L"software\\velkemulationtest", 0, 1, &key) == 0;
    ok &= RegCloseKey(key) == 0;
    ok &= GetLastError() == 73;
    return ok;
}

EXPORT int registry_unterminated(void) {
    handle key;
    if (RegOpenKeyExW(HKCU, L"Software\\VelkEmulationTest", 0, 1, &key)) return 0;
    u16 wide[3] = {0x5555, 0x5555, 0x5555};
    u32 size = 2, type = 0;
    int ok = RegQueryValueExW(key, L"Raw", 0, &type, wide, &size) == 0 && type == 1 && size == 2 && wide[0] == 'X' && wide[1] == 0x5555;
    ok &= RegCloseKey(key) == 0;
    return ok;
}

EXPORT unsigned documented_registry(void) {
    handle key;
    u32 number = 0, size = 4;
    if (RegOpenKeyExA(HKCU, "Software\\Example", 0, 1, &key)) return 0;
    int status = RegQueryValueExA(key, "Count", 0, 0, &number, &size);
    RegCloseKey(key);
    return status ? 0 : number;
}

EXPORT unsigned registry_boundaries(unsigned mode) {
    handle key;
    u32 size = 0;
    if (mode == 0) return RegOpenKeyExA(HKCU, "Software\\VelkEmulationTest", 1, 1, &key);
    if (mode == 1) return RegOpenKeyExA(HKCU, "Software\\MissingKey", 0, 1, &key);
    if (mode == 2) return RegCloseKey((handle)(word)7);
    if (mode == 3) return RegOpenKeyExA(HKCU, "Software\\VelkEmulationTest", 0, 0x200, &key);
    if (RegOpenKeyExA(HKCU, "Software\\VelkEmulationTest", 0, mode == 4 ? 0 : 1, &key)) return 99;
    unsigned status;
    if (mode == 4) status = RegQueryValueExA(key, "Number", 0, 0, 0, &size);
    else if (mode == 5) status = RegQueryValueExA(key, "Number", &size, 0, 0, &size);
    else status = RegQueryValueExA(key, "Number", 0, 0, &size, 0);
    RegCloseKey(key);
    return status;
}

static void registry_output(void) {
    printf("%d\n", registry_values());
    for (unsigned mode = 0; mode <= 6; mode++) {
        if (mode == 1 || mode >= 4) printf("%u %u\n", mode, registry_boundaries(mode));
    }
}

EXPORT void entry(void) {
    registry_output();
    ExitProcess(37);
}

EXPORT void native_entry(void) {
    handle key;
    if (RegCreateKeyExW(HKCU, L"Software\\VelkEmulationTest", 0, 0, 0, 0xf003f, 0, &key, 0)) ExitProcess(99);
    u32 number = 0x89abcdef;
    const unsigned char bytes[] = {0, 0xff, 7};
    int status = RegSetValueExW(key, L"Number", 0, 4, &number, 4);
    status |= RegSetValueExW(key, L"Text", 0, 1, L"Hello", 12);
    status |= RegSetValueExW(key, L"", 0, 1, L"日", 4);
    status |= RegSetValueExW(key, L"Bytes", 0, 3, bytes, 3);
    RegCloseKey(key);
    if (status) ExitProcess(99);
    registry_output();
    RegDeleteKeyW(HKCU, L"Software\\VelkEmulationTest");
    ExitProcess(37);
}
