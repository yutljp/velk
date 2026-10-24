__declspec(dllimport) int imported_value(int value);
__declspec(dllexport) __declspec(noinline) int choose_filter(int value) { return value & 1; }

__declspec(dllexport) int seh_except(int value) {
    __try { return imported_value(value); }
    __except (choose_filter(value)) { return -7; }
}

__declspec(dllexport) int seh_finally(int value) {
    volatile int result = value;
    __try { result = imported_value(value); }
    __finally { result += 3; }
    return result;
}

__declspec(dllexport) int seh_nested(int value) {
    __try {
        __try { return imported_value(value); }
        __finally { imported_value(9); }
    } __except (1) { return -9; }
}
