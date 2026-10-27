#include <stdarg.h>
#ifdef NATIVE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern char *gets(char *);
#else
typedef __SIZE_TYPE__ size_t;
typedef void FILE;
extern FILE *stdin, *stdout, *stderr;
extern int printf(const char *, ...);
extern int fprintf(FILE *, const char *, ...);
extern int sprintf(char *, const char *, ...);
extern int snprintf(char *, size_t, const char *, ...);
extern int puts(const char *);
extern int putchar(int);
extern int fputs(const char *, FILE *);
extern size_t fwrite(const void *, size_t, size_t, FILE *);
extern long write(int, const void *, size_t);
extern long read(int, void *, size_t);
extern size_t fread(void *, size_t, size_t, FILE *);
extern char *fgets(char *, int, FILE *);
extern char *gets(char *);
extern int getchar(void);
extern int scanf(const char *, ...);
extern int fscanf(FILE *, const char *, ...);
extern int sscanf(const char *, const char *, ...);
extern int strcmp(const char *, const char *);
extern size_t strlen(const char *);
#endif

#ifndef NATIVE
extern int vprintf(const char *, va_list);
extern int vfprintf(FILE *, const char *, va_list);
extern int vsprintf(char *, const char *, va_list);
extern int vsnprintf(char *, size_t, const char *, va_list);
extern int vscanf(const char *, va_list);
extern int vfscanf(FILE *, const char *, va_list);
extern int vsscanf(const char *, const char *, va_list);
#endif

char decoded[64];
int check_flag(void) {
    char input[32];
    if (!fgets(input, sizeof(input), stdin)) return 2;
    int correct = strcmp(input, "flag{input}\n") == 0;
    puts(correct ? "Correct" : "Wrong");
    return correct;
}
char *decode_buffer(void) {
    const unsigned char encoded[] = {53,56,49,49,50,93};
    for (unsigned i = 0; i < sizeof(encoded); ++i) decoded[i] = encoded[i] ^ 93;
    return decoded;
}
int input_decode(void) {
    if (getchar() != -1) return 0;
    const unsigned char encoded[] = {53,56,49,49,50,93};
    for (unsigned i = 0; i < sizeof(encoded); ++i) decoded[i] = encoded[i] ^ 93;
    return (int)strlen(decoded);
}
int format_value(int value) {
    return printf("%d|%i|%u|%x|%X|%o|%+09d|%-12.6d|%#08x|%.0u|%#.0o|%*.*d|%c|%.3s|%%\n",
        value, value, (unsigned)value, (unsigned)value, (unsigned)value, (unsigned)value,
        value, value, (unsigned)value, (unsigned)value, (unsigned)value, -12, 7, value, 'A', "hello");
}
int format_corner(int value) {
    return printf("%hhd|%hhu|%hd|%hu|%08.3d|%-+12d|%#12.9o|%.*s|%*d|%.*d|%.0s|%p\n",
        value, (unsigned)value, value, (unsigned)value, value, value, (unsigned)value,
        2, "hello", -10, value, -1, value, (char *)0, (void *)0);
}
int format_wide(long long value) {
    return printf("%lld|%llu|%llx|%020lld|%zu|%ld|%p\n", value, (unsigned long long)value,
        (unsigned long long)value, value, (size_t)123, (long)-456, (void *)0x1234);
}
int output_calls(void) {
    int count = sprintf(decoded, "%s:%04d", "code", 7);
    int full = snprintf(decoded + 16, 5, "%08x", 0xabcdef);
    fprintf(stderr, "error:%d", 3);
    fputs("out", stdout);
    fputs("err", stderr);
    putchar('!');
    fwrite("ABCD", 2, 2, stdout);
    write(2, "!?", 2);
    return count * 100 + full;
}
int input_calls(void) {
    char a[4] = {0}, b[4] = {0}, c[8] = {0};
    int first = getchar();
    long n = read(0, a, 2);
    size_t count = fread(b, 2, 1, stdin);
    if (!gets(c)) return 99;
    sprintf(decoded, "%c|%s|%s|%s", first, a, b, c);
    return (int)(n * 10 + count);
}
int scan_calls(void) {
    int a = 0, b = 0;
    unsigned c = 0;
    char word[8], letter = 0;
    if (scanf("%d %7s %c", &a, word, &letter) != 3) return 90;
    if (fscanf(stdin, "%i", &b) != 1) return 91;
    if (sscanf("ff", "%x", &c) != 1) return 92;
    sprintf(decoded, "%d|%s|%c|%d|%u", a, word, letter, b, c);
    return 0;
}
int scan_value(void) {
    long long wide = 0;
    signed char small = 0;
    char word[4] = {0};
    int count = scanf("%lld %hhd %*s %3s", &wide, &small, word);
    sprintf(decoded, "%lld|%d|%s", wide, (int)small, word);
    return count;
}

static int print_list(const char *format, ...) {
    va_list args; va_start(args, format);
    int count = vprintf(format, args);
    va_end(args); return count;
}
static int error_list(const char *format, ...) {
    va_list args; va_start(args, format);
    int count = vfprintf(stderr, format, args);
    va_end(args); return count;
}
static int string_list(const char *format, ...) {
    va_list args; va_start(args, format);
    int count = vsprintf(decoded, format, args);
    va_end(args); return count;
}
static int bounded_list(const char *format, ...) {
    va_list args; va_start(args, format);
    int count = vsnprintf(decoded + 16, 5, format, args);
    va_end(args); return count;
}
static int scan_list(const char *format, ...) {
    va_list args; va_start(args, format);
    int count = vscanf(format, args);
    va_end(args); return count;
}
static int scan_file_list(const char *format, ...) {
    va_list args; va_start(args, format);
    int count = vfscanf(stdin, format, args);
    va_end(args); return count;
}
static int scan_string_list(const char *format, ...) {
    va_list args; va_start(args, format);
    int count = vsscanf("27", format, args);
    va_end(args); return count;
}
int variadic_stdout(void) {
    return print_list("%d|%d|%d|%d|%d|%d|%d|%d|%d|%lld\n", 1,2,3,4,5,6,7,8,9, -9223372036854775807LL-1);
}
int variadic_error(void) { return error_list("%s:%d", "error", 3); }
int variadic_string(void) { return string_list("%s:%04d", "code", 7); }
int variadic_bounded(void) { return bounded_list("%08x", 0xabcdef); }
int variadic_scan(void) {
    int value = 0;
    if (scan_list("%d", &value) != 1) return 91;
    sprintf(decoded, "%d", value); return value;
}
int variadic_scan_file(void) {
    int value = 0;
    if (scan_file_list("%d", &value) != 1) return 92;
    sprintf(decoded, "%d", value); return value;
}
int variadic_scan_string(void) {
    int value = 0;
    if (scan_string_list("%d", &value) != 1) return 93;
    sprintf(decoded, "%d", value); return value;
}
int scan_signed(const char *format, const char *input) {
    int value = 0x1234;
    char next = 127;
    int count = sscanf(input, format, &value, &next);
    sprintf(decoded, "%u|%u", (unsigned)value, (unsigned)(unsigned char)next);
    return count;
}
int scan_unsigned(const char *format, const char *input) {
    unsigned value = 0x1234;
    char next = 127;
    int count = sscanf(input, format, &value, &next);
    sprintf(decoded, "%u|%u", value, (unsigned)(unsigned char)next);
    return count;
}
int main(int argc, char **argv) {
#ifdef NATIVE
    setvbuf(stdin, 0, _IONBF, 0);
    if (argc > 3 && (!strcmp(argv[1], "scan_signed") || !strcmp(argv[1], "scan_unsigned"))) {
        int count = !strcmp(argv[1], "scan_signed") ? scan_signed(argv[2], argv[3]) : scan_unsigned(argv[2], argv[3]);
        printf("%s\n%d\n", decoded, count);
        return 0;
    }
    if (argc > 3 && !strcmp(argv[1], "signed")) return printf(argv[2], (int)strtol(argv[3], 0, 10)) < 0;
    if (argc > 3 && !strcmp(argv[1], "unsigned")) return printf(argv[2], (unsigned)strtoul(argv[3], 0, 10)) < 0;
    if (argc > 1 && !strcmp(argv[1], "check")) return check_flag();
    if (argc > 1 && !strcmp(argv[1], "scan")) {
        int count = scan_value();
        printf("%s\n%d\n", decoded, count);
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "input")) {
        int count = input_calls();
        printf("%s\n%d\n", decoded, count);
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "voutput")) {
        int count = variadic_stdout();
        count += variadic_error();
        count += variadic_string();
        count += variadic_bounded();
        printf("%s|%s\n%d\n", decoded, decoded + 16, count);
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "output")) {
        int count = output_calls();
        printf("\n%s|%s\n%d\n", decoded, decoded + 16, count);
        return 0;
    }
    if (argc > 2 && !strcmp(argv[1], "format")) return format_value((int)strtol(argv[2], 0, 0)) < 0;
    if (argc > 2 && !strcmp(argv[1], "corner")) return format_corner((int)strtol(argv[2], 0, 0)) < 0;
    if (argc > 2 && !strcmp(argv[1], "wide")) return format_wide(strtoll(argv[2], 0, 0)) < 0;
#endif
    printf("argc=%d argv0=%s argv1=%s\n", argc, argv[0], argc > 1 ? argv[1] : "");
    return argc;
}
int unsupported_format(void) { return printf("%f", 1.0); }
int unsupported_scan(void) { float value; return scanf("%f", &value); }
int invalid_fd(void) { return (int)write(4, "x", 1); }
int invalid_stream(void) { return fprintf((FILE *)1234, "x"); }
int empty_input(void) { return getchar(); }
int truncated_string(void) { return snprintf((char *)0, 0, "%s", "abc"); }

int write_descriptor(int fd) { return (int)write(fd, "fd", 2); }
int read_descriptor(int fd) { return (int)read(fd, decoded, 2); }

int format_signed(const char *format, int value) { return printf(format, value); }
int format_unsigned(const char *format, unsigned value) { return printf(format, value); }
