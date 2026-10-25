#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <time.h>
#include <math.h>
#include <process.h>
#include <io.h>
#include <errno.h>
#include <locale.h>
#include <ctype.h>

extern __declspec(dllimport) double sin(double);

#define FIXTURE __attribute__((noinline, dllexport))
FIXTURE int crt_stdio(const char *text, FILE *file) { return fputs(text, file); }
FIXTURE void *crt_alloc(size_t count, size_t size) { return calloc(count, size); }
FIXTURE long crt_number(const char *text, char **end) { return strtol(text, end, 10); }
FIXTURE char *crt_string(const char *text, int ch) { return strchr(text, ch); }
FIXTURE size_t crt_wide(const wchar_t *text) { return wcslen(text); }
FIXTURE time_t crt_time(time_t *result) { return time(result); }
FIXTURE double crt_math(double value) { return sin(value); }
FIXTURE int crt_secure(char *out, size_t size, const char *text) { return strcpy_s(out, size, text); }
FIXTURE int crt_wide_secure(wchar_t *out, size_t size, const wchar_t *text) { return wcscpy_s(out, size, text); }
FIXTURE int crt_process(void) { return _getpid(); }
FIXTURE int crt_io(int fd) { return _close(fd); }
FIXTURE int *crt_errno(void) { return _errno(); }
FIXTURE char *crt_locale(int category, const char *name) { return setlocale(category, name); }
FIXTURE int crt_ctype(int value) { return isalpha(value); }
FIXTURE int crt_format(int value) { return printf("%d\n", value); }
void fixture_entry(void) {}
