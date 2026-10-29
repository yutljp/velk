typedef unsigned char u8;
typedef unsigned int u32;
typedef __SIZE_TYPE__ usize;
extern void *memcpy(void *, const void *, usize);
extern void *memmove(void *, const void *, usize);
extern void *memset(void *, int, usize);
extern usize strlen(const char *);
extern usize strcspn(const char *, const char *);
extern int strcmp(const char *, const char *);
extern int strncmp(const char *, const char *, usize);
extern char *strcpy(char *, const char *);
extern void *malloc(usize);
extern void *calloc(usize, usize);
extern void free(void *);
extern void *realloc(void *, usize);
extern void *memchr(const void *, int, usize);
#ifndef NATIVE
extern void *memrchr(const void *, int, usize);
#endif
extern char *strrchr(const char *, int);
extern char *strstr(const char *, const char *);
extern char *strdup(const char *);
extern char *strndup(const char *, usize);
extern int strcasecmp(const char *, const char *);
extern int strncasecmp(const char *, const char *, usize);
extern long strtol(const char *, char **, int);
extern long long strtoll(const char *, char **, int);
extern unsigned long strtoul(const char *, char **, int);
extern unsigned long long strtoull(const char *, char **, int);
extern int atoi(const char *);
extern long atol(const char *);
extern void qsort(void *, usize, usize, int (*)(const void *, const void *));
extern void *bsearch(const void *, const void *, usize, usize, int (*)(const void *, const void *));
#ifndef NATIVE
extern int *__errno_location(void);
#else
#include <errno.h>
#endif
const u8 hook_read_only[4] = { 1, 2, 3, 0 };

u32 hook_copy(u8 *p, u8 *q, usize n) { return memcpy(p, q, n) == p; }
u32 hook_move(u8 *p, u8 *q, usize n) { return memmove(p, q, n) == p; }
u32 hook_set(u8 *p, u8 *q, usize n) { (void)q; return memset(p, 0xa5, n) == p; }
u32 hook_length(u8 *p, u8 *q, usize n) { (void)q; (void)n; return strlen((char *)p); }
u32 hook_compare(u8 *p, u8 *q, usize n) {
    (void)n; int result = strcmp((char *)p, (char *)q);
    return (result > 0) - (result < 0);
}
u32 hook_compare_n(u8 *p, u8 *q, usize n) {
    int result = strncmp((char *)p, (char *)q, n);
    return (result > 0) - (result < 0);
}
u32 hook_string_copy(u8 *p, u8 *q, usize n) { (void)n; return strcpy((char *)p, (char *)q) == (char *)p; }
u32 hook_allocate(u8 *p, u8 *q, usize n) {
    (void)p; (void)q; u8 *a = malloc(n);
    if (!a) return 0;
    if (n) { a[0] = 3; a[n-1] = 7; }
    free(a); return 1;
}
u32 hook_calloc(u8 *p, u8 *q, usize n) {
    (void)p; (void)q; u8 *a = calloc(n, 2);
    if (!a) return 0;
    u32 result = 1;
    for (usize i = 0; i < n * 2; ++i) if (a[i]) result = 2;
    free(a); return result;
}
u32 hook_overflow(u8 *p, u8 *q, usize n) {
    (void)p; (void)q; (void)n; void *a = calloc((usize)-1, 2);
    u32 result = a == (void *)0; free(a); return result;
}
u32 hook_free(u8 *p, u8 *q, usize n) { (void)q; (void)n; free(p); return 7; }
u32 hook_complement_span(u8 *p, u8 *q, usize n) { (void)n; return strcspn((char *)p, (char *)q); }
u32 hook_reallocate(u8 *p, u8 *q, usize n) {
    (void)p; (void)q;
    u8 *a = malloc(4);
    if (!a) return 0;
    a[0] = 3; a[1] = 5; a[2] = 7; a[3] = 9;
    u8 *b = realloc(a, n);
    if (!b && n) { free(a); return 0; }
    u32 result = n >= 2 && b[0] == 3 && b[1] == 5;
    free(b);
    return result;
}
u32 hook_find_byte(u8 *p, u8 *q, usize n) {
    u8 *found = memchr(p, *q, n);
    return found ? (u32)(found - p) : 0xffffffffu;
}
u32 hook_find_byte_reverse(u8 *p, u8 *q, usize n) {
#ifdef NATIVE
    u8 *found = 0;
    for (usize i = 0; i < n; ++i) if (p[i] == *q) found = p + i;
#else
    u8 *found = memrchr(p, *q, n);
#endif
    return found ? (u32)(found - p) : 0xffffffffu;
}
u32 hook_reverse_character(u8 *p, u8 *q, usize n) {
    (void)n; char *found = strrchr((char *)p, *q);
    return found ? (u32)(found - (char *)p) : 0xffffffffu;
}
u32 hook_find_substring(u8 *p, u8 *q, usize n) {
    (void)n; char *found = strstr((char *)p, (char *)q);
    return found ? (u32)(found - (char *)p) : 0xffffffffu;
}
u32 hook_duplicate(u8 *p, u8 *q, usize n) {
    (void)q; (void)n; char *copy = strdup((char *)p);
    if (!copy) return 0;
    u32 result = !__builtin_strcmp(copy, (char *)p);
    free(copy); return result;
}
u32 hook_duplicate_n(u8 *p, u8 *q, usize n) {
    (void)q; char *copy = strndup((char *)p, n);
    if (!copy) return 0;
    u32 result = 1;
    usize length = 0;
    while (length < n && p[length]) ++length;
    for (usize i = 0; i < length; ++i) if (copy[i] != p[i]) result = 0;
    if (copy[length]) result = 0;
    free(copy); return result;
}
u32 hook_compare_case(u8 *p, u8 *q, usize n) {
    (void)n; int result = strcasecmp((char *)p, (char *)q);
    return (result > 0) - (result < 0);
}
u32 hook_compare_case_n(u8 *p, u8 *q, usize n) {
    int result = strncasecmp((char *)p, (char *)q, n);
    return (result > 0) - (result < 0);
}
u32 hook_strtol(u8 *p, u8 *q, usize base) {
    char *end; long value = strtol((char *)p, &end, (int)base);
    q[0] = (u8)(end - (char *)p); return (u32)value;
}
u32 hook_strtoll(u8 *p, u8 *q, usize base) {
    char *end; long long value = strtoll((char *)p, &end, (int)base);
    q[0] = (u8)(end - (char *)p); q[1] = (u8)(value >> 32); return (u32)value;
}
u32 hook_strtoul(u8 *p, u8 *q, usize base) {
    char *end; unsigned long value = strtoul((char *)p, &end, (int)base);
    q[0] = (u8)(end - (char *)p); return (u32)value;
}
u32 hook_strtoull(u8 *p, u8 *q, usize base) {
    char *end; unsigned long long value = strtoull((char *)p, &end, (int)base);
    q[0] = (u8)(end - (char *)p); q[1] = (u8)(value >> 32); return (u32)value;
}
u32 hook_atoi(u8 *p, u8 *q, usize n) { (void)q; (void)n; return (u32)atoi((char *)p); }
u32 hook_atol(u8 *p, u8 *q, usize n) { (void)q; (void)n; return (u32)atol((char *)p); }

u32 hook_strtol_overflow(u8 *p, u8 *q, usize mode) {
    char *end;
    int *error =
#ifdef NATIVE
        &errno;
#else
        __errno_location();
#endif
    *error = 0;
    if (mode == 0) {
        long value = strtol((char *)p, &end, 10);
        q[1] = value == (long)(~0UL >> 1);
    } else if (mode == 1) {
        long value = strtol((char *)p, &end, 10);
        q[1] = value == (long)(1UL << (sizeof(long) * 8 - 1));
    } else if (mode == 2) {
        unsigned long value = strtoul((char *)p, &end, 10);
        q[1] = value == ~0UL;
    } else {
        unsigned long long value = strtoull((char *)p, &end, 10);
        q[1] = value == ~0ULL;
    }
    q[0] = (u8)(end - (char *)p);
    q[2] = *error == 34;
    return q[1] && q[2];
}

static int compare_ints(const void *left, const void *right) {
    int a = *(const int *)left;
    int b = *(const int *)right;
    return (a > b) - (a < b);
}

u32 hook_sort(u8 *p, u8 *q, usize count) {
    qsort(p, count, sizeof(int), compare_ints);
    int *found = bsearch(q, p, count, sizeof(int), compare_ints);
    return found ? (u32)(found - (int *)p + 1) : 0;
}

#ifdef NATIVE
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    u32 (*routines[])(u8 *, u8 *, usize) = { hook_copy, hook_move, hook_set, hook_length,
        hook_compare, hook_compare_n, hook_string_copy, hook_allocate, hook_calloc,
        hook_overflow, hook_free, hook_reallocate, hook_find_byte,
        hook_find_byte_reverse, hook_reverse_character, hook_find_substring,
        hook_duplicate, hook_duplicate_n, hook_compare_case, hook_compare_case_n,
        hook_strtol, hook_strtoll, hook_strtoul, hook_strtoull, hook_atoi, hook_atol,
        hook_strtol_overflow, hook_sort, hook_complement_span };
    u8 bytes[128];
    if (argc != 5 || fread(bytes, 1, sizeof(bytes), stdin) != sizeof(bytes)) return 2;
    unsigned routine = (unsigned)strtoul(argv[1], 0, 10);
    unsigned offset = (unsigned)strtoul(argv[2], 0, 10);
    unsigned source = (unsigned)strtoul(argv[3], 0, 10);
    usize n = strtoul(argv[4], 0, 10);
    if (routine >= sizeof(routines)/sizeof(routines[0]) || offset >= 128 || source >= 128) return 3;
    u32 result = routines[routine](routine == 10 ? (void *)0 : bytes + offset, bytes + source, n);
    if (fwrite(&result, sizeof(result), 1, stdout) != 1 || fwrite(bytes, 1, sizeof(bytes), stdout) != sizeof(bytes)) return 4;
    return 0;
}
#endif
