#include <stdint.h>

/* A frame of more than a page: some targets probe the stack with a call
   before growing it, with the arguments still in their registers. */

__attribute__((noinline)) uint32_t large_frame(uint32_t seed) {
    uint32_t table[1200];
    for (int i = 0; i < 1200; i++)
        table[i] = seed * (uint32_t)i;
    return table[seed % 1200] + seed;
}

__attribute__((noinline)) uint32_t calls_large_frame(uint32_t seed) {
    return large_frame(seed ^ 0x5a5au) + 1;
}

int main(int argc, char **argv) {
    (void)argv;
    return (int)calls_large_frame((uint32_t)argc) & 1;
}
