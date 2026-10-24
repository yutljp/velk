__declspec(dllimport) int imported_value(int value);
extern "C" __declspec(dllexport) int cpp_catch(int value) {
    try { return imported_value(value); }
    catch (...) { return -11; }
}
