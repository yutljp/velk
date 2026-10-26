typedef unsigned char u8;
typedef unsigned int u32;
typedef __SIZE_TYPE__ usize;
extern void *memcpy(void *, const void *, usize);
extern void *memmove(void *, const void *, usize);
extern void *memset(void *, int, usize);
extern usize strlen(const char *);
extern int strcmp(const char *, const char *);
extern int strncmp(const char *, const char *, usize);
extern char *strcpy(char *, const char *);
extern void *malloc(usize);
extern void *calloc(usize, usize);
extern void free(void *);
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

#ifdef NATIVE
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    u32 (*routines[])(u8 *, u8 *, usize) = { hook_copy, hook_move, hook_set, hook_length,
        hook_compare, hook_compare_n, hook_string_copy, hook_allocate, hook_calloc,
        hook_overflow, hook_free };
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
