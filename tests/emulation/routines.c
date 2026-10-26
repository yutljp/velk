typedef unsigned char u8;
typedef unsigned int u32;

__attribute__((noinline)) u32 xor_key(u8 *p, u32 n, u32 key) {
    u32 sum = 0;
    for (u32 i = 0; i < n; ++i) { p[i] ^= key; sum = sum * 33 + p[i]; }
    return sum;
}

__attribute__((noinline)) u32 rolling_xor(u8 *p, u32 n, u32 key) {
    for (u32 i = 0; i < n; ++i) { key = key * 1664525u + 1013904223u; p[i] ^= key >> 24; }
    return key;
}

__attribute__((noinline)) u32 rc4(u8 *p, u32 n, u32 key) {
    u8 state[256];
    u32 j = 0;
    for (u32 i = 0; i < 256; ++i) state[i] = i;
    for (u32 i = 0; i < 256; ++i) {
        j = (j + state[i] + ((key >> ((i & 3) * 8)) & 255)) & 255;
        u8 t = state[i]; state[i] = state[j]; state[j] = t;
    }
    u32 i = 0; j = 0;
    for (u32 k = 0; k < n; ++k) {
        i = (i + 1) & 255; j = (j + state[i]) & 255;
        u8 t = state[i]; state[i] = state[j]; state[j] = t;
        p[k] ^= state[(state[i] + state[j]) & 255];
    }
    return n;
}

__attribute__((noinline)) u32 base64_decode(u8 *p, u32 n, u32 key) {
    (void)key;
    u32 bits = 0, count = 0, out = 0;
    for (u32 i = 0; i < n; ++i) {
        u32 c = p[i], v;
        if (c == '=') break;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+') v = 62;
        else if (c == '/') v = 63;
        else continue;
        bits = (bits << 6) | v; count += 6;
        if (count >= 8) { count -= 8; p[out++] = bits >> count; }
    }
    return out;
}

__attribute__((noinline)) u32 crc32(u8 *p, u32 n, u32 key) {
    u32 crc = ~key;
    for (u32 i = 0; i < n; ++i) {
        crc ^= p[i];
        for (u32 bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1)));
    }
    return ~crc;
}

__attribute__((noinline)) u32 adler32(u8 *p, u32 n, u32 key) {
    (void)key;
    u32 a = 1, b = 0;
    for (u32 i = 0; i < n; ++i) { a = (a + p[i]) % 65521; b = (b + a) % 65521; }
    return (b << 16) | a;
}

__attribute__((noinline)) u32 xtea_decrypt(u8 *p, u32 n, u32 key) {
    u32 keys[4] = { key, key ^ 0xa5a5a5a5u, ~key, key + 0x12345678u };
    for (u32 offset = 0; n - offset >= 8; offset += 8) {
        u32 a = 0, b = 0, sum = 0xc6ef3720u;
        for (u32 i = 0; i < 4; ++i) { a |= (u32)p[offset+i] << (i*8); b |= (u32)p[offset+4+i] << (i*8); }
        for (u32 round = 0; round < 32; ++round) {
            b -= (((a << 4) ^ (a >> 5)) + a) ^ (sum + keys[(sum >> 11) & 3]);
            sum -= 0x9e3779b9u;
            a -= (((b << 4) ^ (b >> 5)) + b) ^ (sum + keys[sum & 3]);
        }
        for (u32 i = 0; i < 4; ++i) { p[offset+i] = a >> (i*8); p[offset+4+i] = b >> (i*8); }
    }
    return n / 8;
}

__attribute__((noinline)) u32 stack_string(u8 *p, u32 n, u32 key) {
    volatile u8 text[8];
    text[0] = 53; text[1] = 56; text[2] = 49; text[3] = 49;
    text[4] = 50; text[5] = 93; text[6] = 127; text[7] = 255;
    u32 sum = 0;
    for (u32 i = 0; i < n; ++i) { p[i] = text[i & 7] ^ key; sum += p[i]; }
    return sum;
}

__attribute__((noinline)) u32 substitution(u8 *p, u32 n, u32 key) {
    static const u8 table[16] = { 12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2 };
    u32 sum = 0;
    for (u32 i = 0; i < n; ++i) { u8 c = p[i] ^ key; p[i] = (table[c >> 4] << 4) | table[c & 15]; sum += p[i]; }
    return sum;
}

__attribute__((noinline)) u32 length_decode(u8 *p, u32 n, u32 key) {
    if (!n) return 0;
    u32 size = p[0];
    if (size > n - 1) size = n - 1;
    for (u32 i = 0; i < size; ++i) p[i] = p[i + 1] ^ key;
    return size;
}

__attribute__((noinline)) u32 recurse(volatile u32 *p) {
    if (!*p) return 1;
    --*p;
    return recurse(p) + 1;
}
__attribute__((noinline)) u32 load_byte(u8 *p) { return *p; }
__attribute__((noinline)) u32 store_byte(u8 *p) { *p = 7; return 0; }
__attribute__((noinline)) u32 spin(volatile u32 *p) { while (*p) {} return *p; }
__attribute__((noinline)) u32 sum3(u32 a, u32 b, u32 c) { return a + b + c; }
__attribute__((noinline)) u32 decode(u8 *p, u32 n, u32 key) { return xor_key(p, n, key); }
const u8 read_only[4] = { 1, 2, 3, 0 };
u8 writable[4] = { 1, 2, 3, 0 };
