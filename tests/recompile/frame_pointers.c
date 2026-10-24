#include <stdint.h>

/* Unoptimized code reaches small locals far from the stack pointer through
   a register holding their address, or through a frame slot holding it. */

__attribute__((noinline)) uint32_t far_locals(uint32_t seed) {
    uint8_t flag = (uint8_t)(seed * 3u);
    uint16_t half = (uint16_t)(seed >> 4);
    uint8_t bytes[6];
    uint32_t big[1100];
    for (int i = 0; i < 6; i++)
        bytes[i] = (uint8_t)(flag + i);
    for (int i = 0; i < 1100; i++)
        big[i] = seed + (uint32_t)i + bytes[i % 6];
    flag ^= bytes[seed % 6u];
    half += (uint16_t)big[seed % 1100u];
    return flag + half + bytes[2] + big[7];
}

int main(int argc, char **argv) {
    (void)argv;
    return (int)far_locals((uint32_t)argc) & 1;
}
