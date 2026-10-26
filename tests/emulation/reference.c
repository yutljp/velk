#include <stdio.h>
#include <stdint.h>
#include "routines.c"

int main(void) {
    u32 (*routines[])(u8 *, u32, u32) = {
        xor_key, rolling_xor, rc4, base64_decode, crc32, adler32,
        xtea_decrypt, stack_string, substitution, length_decode
    };
    u32 header[3];
    u8 buffer[4096];
    while (fread(header, sizeof(header), 1, stdin) == 1) {
        if (header[0] >= sizeof(routines) / sizeof(routines[0]) || header[1] > sizeof(buffer)) return 2;
        if (fread(buffer, 1, header[1], stdin) != header[1]) return 3;
        u32 result = routines[header[0]](buffer, header[1], header[2]);
        if (fwrite(&result, sizeof(result), 1, stdout) != 1 ||
            fwrite(buffer, 1, header[1], stdout) != header[1]) return 4;
    }
    return ferror(stdin) ? 5 : 0;
}
