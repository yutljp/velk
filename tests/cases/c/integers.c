/* Integer widths and idioms. */
typedef _Bool bool;

signed char narrow_add(signed char a, signed char b) { return (signed char)(a + b); }
unsigned short widen_mul(unsigned char a, unsigned char b) { return (unsigned short)(a * b); }
long long mixed_sign(int a, unsigned b) { return (long long)a - (long long)b; }
bool in_range(int x, int lo, int hi) { return x >= lo && x <= hi; }

unsigned rotate_left(unsigned x, unsigned k) { return (x << (k & 31)) | (x >> ((32 - k) & 31)); }

int popcount(unsigned x) {
    int count = 0;
    while (x) {
        x &= x - 1;
        count++;
    }
    return count;
}

unsigned byte_swap(unsigned x) {
    return (x >> 24) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | (x << 24);
}

int min3(int a, int b, int c) {
    int m = a < b ? a : b;
    return m < c ? m : c;
}

long labs_value(long x) { return x < 0 ? -x : x; }

#if defined(__SIZEOF_INT128__)
unsigned long long mul_high(unsigned long long a, unsigned long long b) {
    return (unsigned long long)(((unsigned __int128)a * b) >> 64);
}

#endif
