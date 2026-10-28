int getchar(void) { return -1; }
unsigned long __stack_chk_guard;
void __stack_chk_fail(void) { __builtin_trap(); }
long read(int fd, void *p, unsigned long count) {
    (void)fd; (void)p; (void)count;
    return -1;
}
void *stdin;
int scanf(const char *s, ...) { (void)s; return 0; }
int fscanf(void *f, const char *s, ...) { (void)f; (void)s; return 0; }
int sscanf(const char *s, const char *f, ...) { (void)s; (void)f; return 0; }
char *fgets(char *s, int n, void *f) { (void)s; (void)n; (void)f; return 0; }
char *gets(char *s) { return s; }
long getline(char **s, unsigned long *n, void *f) { (void)s; (void)n; (void)f; return -1; }
int strcmp(const char *a, const char *b) { (void)a; (void)b; return 0; }
int strncmp(const char *a, const char *b, unsigned long n) { (void)n; return strcmp(a,b); }
int memcmp(const void *a, const void *b, unsigned long n) { return strncmp(a,b,n); }
unsigned long strlen(const char *s) { (void)s; return 0; }
unsigned long strnlen(const char *s, unsigned long n) { (void)n; return strlen(s); }
void *memmove(void *a, const void *b, unsigned long n) { (void)b; (void)n; return a; }
void *memcpy(void *a, const void *b, unsigned long n) { (void)b; (void)n; return a; }
void *memset(void *a, int c, unsigned long n) { (void)c; (void)n; return a; }
char *strcpy(char *a, const char *b) { (void)b; return a; }
char *strncpy(char *a, const char *b, unsigned long n) { (void)n; return strcpy(a,b); }
char *strchr(const char *s, int c) { (void)s; (void)c; return 0; }
int atoi(const char *s) { (void)s; return 0; }
long strtol(const char *s, char **e, int b) { (void)e; (void)b; return atoi(s); }
int toupper(int c) { return c; }
int tolower(int c) { return c; }
int puts(const char *s) { (void)s; return 0; }
int printf(const char *s, ...) { (void)s; return 0; }
