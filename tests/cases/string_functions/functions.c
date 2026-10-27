typedef __SIZE_TYPE__ size_t;

size_t length(const unsigned char *source) {
    size_t n = 0;
    while (source[n]) ++n;
    return n;
}
int compare(const unsigned char *a, const unsigned char *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return (int)*a - (int)*b;
}

int memory_compare(const unsigned char *a, const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}
int string_compare(const unsigned char *a, const unsigned char *b) {
    for (;;) {
        if (*a < *b) return -1;
        if (*a > *b) return 1;
        if (!*a) return 0;
        ++a; ++b;
    }
}
int bounded_compare(const unsigned char *a, const unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
        if (!a[i]) return 0;
    }
    return 0;
}
unsigned char *find(const unsigned char *source, int value) {
    for (;;) {
        if (*source == (unsigned char)value) return (unsigned char *)source;
        if (!*source) return (void *)0;
        ++source;
    }
}
void *copy_literal(void *destination) {
    return __builtin_memcpy(destination, "copy", 5);
}
unsigned char *string_copy(unsigned char *destination, const unsigned char *source) {
    unsigned char *result = destination;
    do { *destination++ = *source; } while (*source++);
    return result;
}
int short_compare(const unsigned char *a, const unsigned char *b) {
    if (a[0] < b[0]) return -1;
    if (a[0] > b[0]) return 1;
    if (a[1] < b[1]) return -1;
    if (a[1] > b[1]) return 1;
    return (a[2] > b[2]) - (a[2] < b[2]);
}
int short_string_compare(const unsigned char *a, const unsigned char *b) {
    if (a[0] < b[0]) return -1;
    if (a[0] > b[0]) return 1;
    if (!a[0]) return 0;
    if (a[1] < b[1]) return -1;
    if (a[1] > b[1]) return 1;
    if (!a[1]) return 0;
    return (a[2] > b[2]) - (a[2] < b[2]);
}
size_t word_length(const unsigned char *source) {
    const unsigned char *p = source;
    for (;;) {
        __UINT64_TYPE__ word;
        __builtin_memcpy(&word, p, 8);
        if ((word - 0x0101010101010101ULL) & ~word & 0x8080808080808080ULL) {
            while (*p) ++p;
            return (size_t)(p - source);
        }
        p += 8;
    }
}
int vector_compare(const unsigned char *a, const unsigned char *b) {
    typedef unsigned char bytes16 __attribute__((vector_size(16)));
    for (size_t offset = 0; offset < 32; offset += 16) {
        bytes16 left, right;
        __builtin_memcpy(&left, a + offset, 16);
        __builtin_memcpy(&right, b + offset, 16);
        bytes16 equal = left == right;
        for (size_t i = 0; i < 16; ++i) {
            if (!equal[i]) return (a[offset + i] > b[offset + i]) - (a[offset + i] < b[offset + i]);
        }
    }
    return 0;
}
size_t vector_length(const unsigned char *source) {
    typedef unsigned char bytes16 __attribute__((vector_size(16)));
    for (size_t offset = 0;; offset += 16) {
        bytes16 word;
        __builtin_memcpy(&word, source + offset, 16);
        bytes16 zero = word == (bytes16){0};
        __UINT64_TYPE__ halves[2];
        __builtin_memcpy(halves, &zero, 16);
        if (halves[0] | halves[1]) {
            for (size_t i = 0; i < 16; ++i) if (!source[offset + i]) return offset + i;
        }
    }
}
size_t length_plus_one(const unsigned char *source) {
    size_t n = 0;
    while (source[n]) ++n;
    return n + 1;
}
int bounded_off_by_one(const unsigned char *a, const unsigned char *b, size_t n) {
    for (size_t i = 0; i <= n; ++i) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}
int signed_compare(const signed char *a, const signed char *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return (int)*a - (int)*b;
}
void copy_without_zero(unsigned char *destination, const unsigned char *source) {
    while (*source) *destination++ = *source++;
}
