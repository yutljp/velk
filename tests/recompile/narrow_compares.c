#include <stdint.h>

/* Signed comparisons of narrow values with negative constants. */

__attribute__((noinline)) uint32_t narrow_signed_loops(uint32_t seed) {
    int16_t half;
    int8_t byte;
    uint32_t count = 0;
    for (half = (int16_t)(seed % 7u) - 11; half <= -22; --half)
        count++;
    for (byte = (int8_t)(seed % 5u) - 3; byte <= -100; --byte)
        count += 2;
    if (half > -3)
        count += 5;
    return count + (uint32_t)half + (uint32_t)byte;
}

int main(int argc, char **argv) {
    (void)argv;
    return (int)narrow_signed_loops((uint32_t)argc) & 1;
}
