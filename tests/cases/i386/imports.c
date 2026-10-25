__declspec(dllimport) int abs(int x);
__declspec(dllexport) int import_call(int x) { return abs(x) + 3; }
