__declspec(dllexport) int __cdecl cdecl_add(int a, int b) { return a + b; }
__declspec(dllexport) int __stdcall stdcall_add(int a, int b) { return a + b; }
__declspec(dllexport) int __fastcall fastcall_add(int a, int b, int c) { return a + b + c; }
__declspec(dllexport) int __thiscall thiscall_add(int a, int b) { return a + b; }
__declspec(dllexport) int call_conventions(int x) {
    return cdecl_add(x, 1) + stdcall_add(x, 2) + fastcall_add(x, 3, 4) + thiscall_add(x, 5);
}
