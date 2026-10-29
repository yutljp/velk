typedef unsigned long size_t;
extern int getchar(void);
extern int scanf(const char *, ...);
extern int fscanf(void *, const char *, ...);
extern int sscanf(const char *, const char *, ...);
extern char *fgets(char *, int, void *);
extern char *gets(char *);
extern long getline(char **, size_t *, void *);
#ifdef __APPLE__
extern void *__stdinp;
#define stdin __stdinp
#else
extern void *stdin;
#endif
extern long read(int, void *, size_t);
extern int strcmp(const char *, const char *);
extern int strncmp(const char *, const char *, size_t);
extern int memcmp(const void *, const void *, size_t);
extern size_t strlen(const char *);
extern size_t strnlen(const char *, size_t);
extern void *memmove(void *, const void *, size_t);
extern void *memcpy(void *, const void *, size_t);
extern void *memset(void *, int, size_t);
extern char *strcpy(char *, const char *);
extern char *strncpy(char *, const char *, size_t);
extern char *strchr(const char *, int);
extern int atoi(const char *);
extern long strtol(const char *, char **, int);
extern int toupper(int);
extern int tolower(int);
extern int puts(const char *);
extern int printf(const char *, ...);

int scan_stream(void) { char s[4]; return fscanf(stdin, "%3s", s) == 1 && strcmp(s, "yes") == 0; }
int scan_stack(void) { char s[9]; return scanf("%c%c%c%c%c%c%c%c%c", &s[0], &s[1], &s[2], &s[3], &s[4], &s[5], &s[6], &s[7], &s[8]) == 9 && memcmp(s, "abcdefghi", 9) == 0; }
int scan_decimal(void) { int n = 0; return scanf("%2d", &n) == 1 && n == 42; }
int scan_signed(void) { int n = 7; return scanf("%d", &n) == 1 && n == -42 && getchar() == '!'; }
int scan_digit_after_no_eof(void) { int n = 0; char c = 0; return scanf("%d%c", &n, &c) == 2 && n == -42 && c == '1'; }
int scan_signed_min(void) { int n = 0; return scanf("%d", &n) == 1 && n == (-2147483647 - 1); }
int scan_invalid(void) { int n = 7; return scanf("%d", &n) == 0 && n == 7 && getchar() == 'x'; }
int scan_eof(void) { int n = 7; return scanf("%d", &n) == -1 && n == 7; }
int scan_unsigned_sign(void) { unsigned n = 7; return scanf("%u", &n) == 1 && n == ~0u && getchar() == '!'; }
int scan_many(void) {
    int n[13];
    for (unsigned i = 0; i < 13; ++i)
        if (scanf("%d", &n[i]) != 1) return 0;
    for (unsigned i = 0; i < 13; ++i)
        if (n[i] + n[(i + 1) % 13] != (int)(i % 9 + (i + 1) % 13 % 9)) return 0;
    return 1;
}
int scan_relations(const char *input) {
    int n[13];
    if (sscanf(input, "%1d%1d%1d%1d%1d%1d%1d%1d%1d%1d%1d%1d%1d",
               &n[0], &n[1], &n[2], &n[3], &n[4], &n[5], &n[6],
               &n[7], &n[8], &n[9], &n[10], &n[11], &n[12]) != 13) return 0;
    for (unsigned i = 0; i < 13; ++i)
        if (n[i] + n[(i + 1) % 13] != (int)(i % 9 + (i + 1) % 13 % 9)) return 0;
    return 1;
}
int scan_unsigned(void) { unsigned n = 0; return scanf("%2u", &n) == 1 && n == 42; }
int scan_hex(void) { unsigned n = 0; return scanf("%2x", &n) == 1 && n == 42; }
int scan_text(void) { char s[4]; return scanf("%3s", s) == 1 && strcmp(s, "yes") == 0; }
int scan_characters(void) { char s[3]; return scanf("%3c", s) == 1 && memcmp(s, "yes", 3) == 0; }
int scan_string(void) { unsigned n = 0; char s[4]; if (!gets(s)) return 0; return sscanf(s, "%2u", &n) == 1 && n == 42; }
int line_compare(void) { char s[5]; return fgets(s, 5, stdin) && strncmp(s, "yes", 3) == 0; }
int allocated_line(void) { char *s = 0; size_t n = 0; return getline(&s, &n, stdin) == 3 && memcmp(s, "yes", 3) == 0; }
int integer_check(void) { char s[4]; return gets(s) && atoi(s) == 42; }
int integer_hex(void) { char s[4], *end; if (!gets(s)) return 0; long n = strtol(s, &end, 16); return n == 42 && *end == 0; }
int copy_check(void) {
    char a[4], b[4];
    if (read(0, a, 3) != 3) return 0;
    a[3] = 0;
    memset(b, 0, 4); memcpy(b, a, 3);
    if (strlen(b) != 3 || strnlen(b, 2) != 2) return 0;
    memmove(b + 1, b, 2);
    if (b[1] != a[0] || b[2] != a[1]) return 0;
    memmove(b, a, 3);
    strcpy(a, b); strncpy(b, a, 4);
    return strchr(b, 'e') == b + 1 && strcmp(a, "yes") == 0;
}
int output_check(void) { int c = getchar(); puts("ok"); printf("%s %%", "ok"); printf("%c %u %x %d", c, (unsigned)c, (unsigned)c, -c); printf(" %u %u %u %u %u %u %u %u %u", (unsigned)c, (unsigned)c, (unsigned)c, (unsigned)c, (unsigned)c, (unsigned)c, (unsigned)c, (unsigned)c, (unsigned)c); return toupper(c) == 'Y' && tolower(c) == 'y'; }
int bound_descriptor(void) { char c; return read(7, &c, 1) == 1 && c == 'y'; }
__attribute__((noinline)) int stack_check(unsigned long a, unsigned long b, unsigned long c, unsigned long d, unsigned long e, unsigned long f, unsigned long g, unsigned long h, unsigned long i, unsigned long j) {
    return a == 1 && f == 6 && g == 7 && i == 9 && j == 42 && b+c+d+e+h == 22;
}
int switch_check(unsigned n) {
    int state = 0;
    switch (n) {
    case 0: state = puts("zero"); break;
    case 1: state = printf("one %u", n); break;
    case 2: state = getchar(); break;
    case 3: { char c; state = (int)read(0, &c, 1); break; }
    case 4: state = puts("four"); break;
    case 5: state = tolower((int)n); break;
    default: return 0;
    }
    return n == 4 && state >= 0;
}
int even_predicate(unsigned x) { if ((x * (x + 1)) & 1) return 2; return x == 42; }
int square_predicate(unsigned x, unsigned y) { if (7*y*y-1 == x*x) return 2; return x == y; }
int normal_predicate(unsigned x) { if (x == 42) return 1; return 0; }
__attribute__((noinline)) int branch_helper(unsigned x) { if (x == 42) return 1; return 0; }
int repeated_branch(unsigned x) { int a = branch_helper(42); int b = branch_helper(43); return a+b+(x == 1); }
long integer_value(const char *s, unsigned base) { return strtol(s, 0, base); }
unsigned long integer_end(const char *s, unsigned base) { char *end; strtol(s, &end, base); return (unsigned long)(end-s); }
unsigned case_value(unsigned c) { return ((unsigned)toupper((int)c) << 8) ^ (unsigned)tolower((int)c); }

long signed_identity(long value) { return value; }

int unreachable_branches(unsigned x) { if ((x*(x+1)) & 1) { if (x == 42) return 2; return 3; } return 0; }

int argv_one(int argc, char **argv) { return argc == 1 && argv[1] == 0 && argv[0][0] == 'y' && argv[0][1] == 0; }
int argv_two(int argc, char **argv) { return argc == 2 && argv[2] == 0 && argv[0][0] == 0 && strcmp(argv[1], "yes") == 0; }
int argv_three(int argc, char **argv) { return argc == 3 && argv[3] == 0 && argv[0][0] == 'x' && argv[1][0] == 0 && strcmp(argv[2], "yes") == 0; }
