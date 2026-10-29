__declspec(dllimport) unsigned __stdcall UnknownWindowsApi(void);
__declspec(dllimport) void *__stdcall GetModuleHandleA(const char *);
__declspec(dllimport) void *__stdcall GetProcAddress(void *, const char *);
__declspec(dllexport) unsigned unknown_import(void) { return UnknownWindowsApi(); }
__declspec(dllexport) unsigned unknown_export(void) {
    unsigned (__stdcall *function)(void) = GetProcAddress(GetModuleHandleA("kernel32.dll"), "UnknownWindowsApi");
    return function();
}
