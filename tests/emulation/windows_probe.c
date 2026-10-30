__declspec(dllimport) void __stdcall ExitProcess(unsigned);

__declspec(dllexport) void entry(void) {
    ExitProcess(37);
}
