#include <stdint.h>

/* Arrays filled by index whose elements are also read at fixed offsets: an
   unoptimized build reads those elements as separate frame slots. */

__attribute__((noinline)) uint32_t indexed_bytes(uint32_t seed) {
    uint8_t bytes[6];
    for (int i = 0; i < 6; i++)
        bytes[i] = (uint8_t)(seed + i);
    return bytes[1] * 3u + bytes[4];
}

__attribute__((noinline)) uint32_t indexed_words(uint32_t seed) {
    uint32_t before = seed ^ 0x55u;
    int32_t words[3];
    for (int i = 0; i < 3; i++)
        words[i] = (int32_t)(seed * (uint32_t)(i + 7));
    words[1] &= (int32_t)seed;
    return (uint32_t)words[1] + (uint32_t)words[2] + before;
}

int main(int argc, char **argv) {
    (void)argv;
    return (int)(indexed_bytes((uint32_t)argc) + indexed_words((uint32_t)argc)) & 1;
}
