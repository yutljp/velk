#include "../emulation/routines.c"
#include "data.h"

__attribute__((noinline)) void *memcpy(void *dst, const void *src, unsigned long n) {
    u8 *d = dst;
    const u8 *s = src;
    for (unsigned long i = 0; i < n; ++i) d[i] = s[i];
    return dst;
}

__attribute__((noinline)) void *memset(void *dst, int value, unsigned long n) {
    u8 *d = dst;
    for (unsigned long i = 0; i < n; ++i) d[i] = (u8)value;
    return dst;
}

__attribute__((noinline)) unsigned long strlen(const char *p) {
    unsigned long n = 0;
    while (p[n]) ++n;
    return n;
}

__attribute__((noinline)) u32 base64_text(u8 *p, u32 n) {
    u32 count = base64_decode(p, n, 0);
    p[count] = 0;
    return count;
}
u8 custom_alphabet[] = "/+9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA";
u8 custom_data[] = "nIqMi5CS356Tj5eenZqL";
u32 case_custom_base64(void) {
    base64_custom_text(custom_data, sizeof(custom_data) - 1, custom_alphabet);
    return custom_data[0];
}

u32 case_xor(void) { xor_key(xor_data, sizeof(xor_data), 93); return xor_data[0]; }
u8 url_data[] = {
    'h'^93, 't'^93, 't'^93, 'p'^93, 's'^93, ':'^93, '/'^93, '/'^93,
    'd'^93, 'e'^93, 'c'^93, 'o'^93, 'd'^93, 'e'^93, 'd'^93, '.'^93,
    'e'^93, 'x'^93, 'a'^93, 'm'^93, 'p'^93, 'l'^93, 'e'^93, '.'^93,
    'c'^93, 'o'^93, 'm'^93, '/'^93, 'x'^93, 0^93
};
u32 case_url(void) { xor_key(url_data, sizeof(url_data), 93); return url_data[0]; }
u8 config_data[] = { 53, 50, 46, 41, 96, 56, 37, 60, 48, 45, 49, 56, 115, 41, 56, 46, 41, 102, 45, 50, 47, 41, 96, 105, 105, 110, 93 };
u32 case_config(void) {
    xor_key(config_data, sizeof(config_data), 93);
    strtok((char *)config_data, ";");
    return config_data[0];
}
u8 add_data[] = { ('a' - 7), ('d' - 7), ('d' - 7), (' ' - 7), ('s' - 7), ('a' - 7), ('m' - 7), ('p' - 7), ('l' - 7), ('e' - 7), (' ' - 7), ('t' - 7), ('e' - 7), ('x' - 7), ('t' - 7), (0 - 7) };
u32 case_add(void) { add_key(add_data, sizeof(add_data), 7); return add_data[0]; }
u8 subtract_data[] = { ('s' + 9), ('u' + 9), ('b' + 9), (' ' + 9), ('s' + 9), ('a' + 9), ('m' + 9), ('p' + 9), ('l' + 9), ('e' + 9), (' ' + 9), ('t' + 9), ('e' + 9), ('x' + 9), ('t' + 9), (0 + 9) };
u32 case_subtract(void) { subtract_key(subtract_data, sizeof(subtract_data), 9); return subtract_data[0]; }
u8 rotate_data[] = {
#define ROL3(value) ((u8)(((u32)(value) << 3) | ((u32)(value) >> 5)))
    ROL3('r'), ROL3('o'), ROL3('t'), ROL3(' '), ROL3('s'), ROL3('a'),
    ROL3('m'), ROL3('p'), ROL3('l'), ROL3('e'), ROL3(' '), ROL3('t'),
    ROL3('e'), ROL3('x'), ROL3('t'), 0
};
#undef ROL3
u32 case_rotate(void) { rotate_right(rotate_data, sizeof(rotate_data) - 1, 3); return rotate_data[0]; }
u8 terminated_data[] = { 37, 50, 47, 125, 46, 60, 48, 45, 49, 56, 125, 41, 56, 37, 41, 0 };
u32 case_known_terminator(void) {
    xor_key(terminated_data, sizeof(terminated_data) - 1, 93);
    return terminated_data[0];
}
u32 case_rolling(void) { rolling_xor(rolling_data, sizeof(rolling_data), 0x12345678); return rolling_data[0]; }
u32 case_rc4(void) { rc4(rc4_data, sizeof(rc4_data), 0x12345678); return rc4_data[0]; }
u32 case_base64(void) { base64_text(base64_data, sizeof(base64_data) - 1); return base64_data[0]; }
u32 case_many(void) {
    xor_key(many_a_data, sizeof(many_a_data), 93);
    xor_key(many_b_data, sizeof(many_b_data), 93);
    return many_a_data[0] + many_b_data[0];
}
u32 case_bulk(void) {
    for (u32 i = 0; i < 32; ++i) xor_key(bulk_data[i], sizeof(bulk_data[i]), bulk_keys[i]);
    return bulk_data[31][0];
}
u32 case_utf8(void) { xor_key(utf8_data, sizeof(utf8_data), 93); return utf8_data[0]; }
u32 case_wide(void) { xor_key(wide_data, sizeof(wide_data), 93); return wide_data[0]; }
u32 case_comment(void) { xor_key(comment_data, sizeof(comment_data), 93); return comment_data[0]; }
u32 case_inline(void) {
    volatile u8 p[13] = {52, 51, 49, 52, 51, 56, 125, 46, 41, 60, 62, 54, 93};
    for (u32 i = 0; i < sizeof(p); ++i) p[i] ^= 93;
    return strlen((const char *)p);
}
u32 case_stack(void) {
    volatile u8 p[12];
    p[0]='s'; p[1]='t'; p[2]='a'; p[3]='c'; p[4]='k'; p[5]=' ';
    p[6]='b'; p[7]='y'; p[8]='t'; p[9]='e'; p[10]='s'; p[11]=0;
    return strlen((const char *)p);
}
u32 case_global_inline(void) {
    for (u32 i = 0; i < sizeof(inline_global); ++i) inline_global[i] ^= 93;
    return strlen((const char *)inline_global);
}

u32 unknown_key(u32 key) { xor_key(xor_data, sizeof(xor_data), key); return 0; }
u32 unknown_buffer(u8 *p) { xor_key(p, 16, 93); return 0; }
u32 unknown_stack(void) { u8 p[16]; xor_key(p, sizeof(p), 93); return 0; }
u8 ordinary_text[] = "ordinary text";
u32 unchanged_text(void) { xor_key(ordinary_text, sizeof(ordinary_text), 0); return 0; }
u32 unchanged_terminated_text(void) { xor_key(ordinary_text, sizeof(ordinary_text) - 1, 0); return 0; }
u32 plain_copy(void) {
    volatile u8 p[12];
    const volatile char *s = "plain bytes";
    for (u32 i = 0; i < sizeof(p); ++i) p[i] = s[i];
    return strlen((const char *)p);
}
__attribute__((noinline)) u32 endless_decode(u8 *p, u32 n, u32 key) {
    xor_key(p,n,key);
    for (;;) ++p[0];
}
u32 never_finishes(void) { endless_decode(xor_data, sizeof(xor_data), 93); return 0; }
u32 unrelated;
__attribute__((noinline)) u32 writes_elsewhere(u8 *p, u32 n, u32 key) {
    xor_key(p,n,key); unrelated = 7; return 0;
}
u32 unexpected_write(void) { writes_elsewhere(xor_data, sizeof(xor_data), 93); return 0; }
struct { u8 bytes[16]; u32 count; } encoded_record;
__attribute__((noinline)) u32 updates_count(u8 *p, u32 key) {
    xor_key(p, sizeof(encoded_record.bytes), key);
    ++encoded_record.count;
    return 0;
}
u32 unexpected_nearby_write(void) {
    for (u32 i = 0; i < sizeof(encoded_record.bytes); ++i) encoded_record.bytes[i] = xor_data[i];
    updates_count(encoded_record.bytes, 93);
    return 0;
}
__attribute__((noinline)) u32 trapped_decoder(u8 *p, u32 n, u32 key) {
    xor_key(p,n,key); __builtin_trap();
}
u32 stops_on_trap(void) { trapped_decoder(xor_data, sizeof(xor_data), 93); return 0; }
#if defined(__i386__) || defined(__x86_64__)
__attribute__((noinline)) u32 corrupt_return(u8 *p, u32 n, u32 key) {
    xor_key(p,n,key); ((void **)__builtin_frame_address(0))[1] = 0; return 0;
}
u32 changed_return(void) { corrupt_return(xor_data, sizeof(xor_data), 93); return 0; }
#endif

#ifdef NATIVE
#include <stdio.h>
int main(void) {
    case_xor(); puts((const char *)xor_data);
    case_url(); puts((const char *)url_data);
    case_config(); puts((const char *)config_data);
    case_add(); puts((const char *)add_data);
    case_subtract(); puts((const char *)subtract_data);
    case_rotate(); puts((const char *)rotate_data);
    case_rolling(); puts((const char *)rolling_data);
    case_rc4(); puts((const char *)rc4_data);
    case_base64(); puts((const char *)base64_data);
    case_custom_base64(); puts((const char *)custom_data);
    case_many(); puts((const char *)many_a_data); puts((const char *)many_b_data);
    printf("%u %u\n", case_inline(), case_stack());
    case_bulk();
    for (u32 i = 0; i < 32; ++i) puts((const char *)bulk_data[i]);
    case_utf8(); puts((const char *)utf8_data);
    case_wide();
    for (u32 i = 0; wide_data[i]; i += 2) putchar(wide_data[i]);
    putchar('\n');
    case_global_inline(); puts((const char *)inline_global);
    case_known_terminator(); puts((const char *)terminated_data);
    return 0;
}
#endif
