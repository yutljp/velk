typedef unsigned long long word;
#define NOINLINE __attribute__((noinline))
NOINLINE word mba_add(word x, word y) { return (x ^ y) + 2 * (x & y); }
NOINLINE word mba_xor(word x, word y) { return x + y - 2 * (x & y); }
NOINLINE word mba_or(word x, word y) { return x + y - (x & y); }
NOINLINE word mba_identity(word x, word y) { return (x | y) + (x & y) - y; }
NOINLINE word mba_constant(word x, word y) { return (x ^ y) + 2 * (x & y) - x - y + 42; }
NOINLINE word mba_scaled(word x, word y) { return 7 * ((x ^ y) + 2 * (x & y)) - 7 * x; }
NOINLINE word mba_square(word x, word y) {
    word sum = (x ^ y) + 2 * (x & y);
    return sum * sum - x * x - y * y;
}
NOINLINE word different_coefficient(word x, word y) { return (x ^ y) + 3 * (x & y); }
NOINLINE word unchanged_shift(word x, word y) { return (x ^ y) + ((x & y) >> 1); }
NOINLINE unsigned int mba_add32(unsigned int x, unsigned int y) { return (x ^ y) + 2u * (x & y); }
NOINLINE unsigned short mba_add16(unsigned short x, unsigned short y) { return (x ^ y) + 2u * (x & y); }
NOINLINE unsigned char mba_add8(unsigned char x, unsigned char y) { return (x ^ y) + 2u * (x & y); }
NOINLINE word mba_product(word x, word y) { return ((x ^ y) + 2 * (x & y)) * x - x * x; }
