typedef __SIZE_TYPE__ size_t;

void fill13(void *destination) { __builtin_memset(destination, 0xab, 13); }
void fill24(void *destination) { __builtin_memset(destination, 0xab, 24); }
void zero13(void *destination) { __builtin_memset(destination, 0, 13); }
void copy24(void *destination, const void *source) {
    __builtin_memcpy(destination, source, 24);
}
void move16(void *destination, const void *source) {
    __builtin_memmove(destination, source, 16);
}
size_t length(const unsigned char *source) {
    size_t n = 0;
    while (source[n]) ++n;
    return n;
}
int compare(const unsigned char *a, const unsigned char *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return (int)*a - (int)*b;
}
