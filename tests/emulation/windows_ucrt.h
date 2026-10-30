API void *__acrt_iob_func(unsigned);
API int __stdio_common_vfprintf(unsigned long long, void *, const char *, void *, __builtin_va_list);
API int __stdio_common_vsprintf(unsigned long long, char *, size_t, const char *, void *, __builtin_va_list);
API int __stdio_common_vsscanf(unsigned long long, const char *, size_t, const char *, void *, __builtin_va_list);
API int _crt_atexit(void (*)(void));

static int ucrt_printf(const char *format, ...) {
    __builtin_va_list args;
    __builtin_va_start(args, format);
    int result = __stdio_common_vfprintf(0, __acrt_iob_func(1), format, 0, args);
    __builtin_va_end(args);
    return result;
}

static int ucrt_fprintf(void *stream, const char *format, ...) {
    __builtin_va_list args;
    __builtin_va_start(args, format);
    int result = __stdio_common_vfprintf(0, stream, format, 0, args);
    __builtin_va_end(args);
    return result;
}

static int vsprintf(char *output, const char *format, __builtin_va_list args) {
    return __stdio_common_vsprintf(1, output, (size_t)-1, format, 0, args);
}

static int ucrt_sprintf(char *output, const char *format, ...) {
    __builtin_va_list args;
    __builtin_va_start(args, format);
    int result = vsprintf(output, format, args);
    __builtin_va_end(args);
    return result;
}

static int ucrt_snprintf(char *output, size_t size, const char *format, ...) {
    __builtin_va_list args;
    __builtin_va_start(args, format);
    int result = __stdio_common_vsprintf(2, output, size, format, 0, args);
    __builtin_va_end(args);
    return result;
}

static int ucrt_sscanf(const char *input, const char *format, ...) {
    __builtin_va_list args;
    __builtin_va_start(args, format);
    int result = __stdio_common_vsscanf(0, input, (size_t)-1, format, 0, args);
    __builtin_va_end(args);
    return result;
}

static int atexit(void (*callback)(void)) { return _crt_atexit(callback); }
static void *_onexit(void *callback) {
    return _crt_atexit((void (*)(void))callback) == 0 ? callback : 0;
}

// Variadic prologues spill all argument registers, including unused ones.
#define printf(...) ucrt_printf(__VA_ARGS__, 0, 0, 0)
#define fprintf(...) ucrt_fprintf(__VA_ARGS__, 0, 0)
#define sprintf(...) ucrt_sprintf(__VA_ARGS__, 0, 0)
#define snprintf(...) ucrt_snprintf(__VA_ARGS__, 0)
#define sscanf(...) ucrt_sscanf(__VA_ARGS__, 0, 0)
