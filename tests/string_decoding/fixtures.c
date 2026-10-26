#include "../emulation/routines.c"
#include "data.h"

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

u32 case_xor(void) { xor_key(xor_data, sizeof(xor_data), 93); return xor_data[0]; }
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
    volatile u8 p[13];
    p[0]=52; p[1]=51; p[2]=49; p[3]=52; p[4]=51; p[5]=56; p[6]=125;
    p[7]=46; p[8]=41; p[9]=60; p[10]=62; p[11]=54; p[12]=93;
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
    case_rolling(); puts((const char *)rolling_data);
    case_rc4(); puts((const char *)rc4_data);
    case_base64(); puts((const char *)base64_data);
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
