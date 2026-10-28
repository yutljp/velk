#include <stdio.h>
#include <string.h>

extern unsigned long tail_length(const char *);
extern unsigned long tail_import(const char *);
extern unsigned long nested_tail(const char *);
extern int tail_scan(const char *, const char *, ...);

int main(void) {
    char bytes[9] = {0};
    size_t count = fread(bytes, 1, 8, stdin);
    if (count != 4 && count != 7) return 2;
    unsigned long length = strlen(bytes);
    char output[7] = {0};
    int scanned = tail_scan(bytes, "%c%c%c%c%c%c%c", &output[0], &output[1], &output[2],
                            &output[3], &output[4], &output[5], &output[6]);
    if (scanned != (int)(length < 7 ? length : 7)) return 3;
    if (memcmp(bytes, output, (size_t)scanned) != 0) return 4;
    return tail_length(bytes) != length || tail_import(bytes) != length ||
           nested_tail(bytes) != length + 7;
}
