typedef unsigned int u32;
typedef unsigned long long u64;

u32 original(u32 x) { return x + 7u; }
u64 original64(u64 x) { return x + 7u; }
u32 original_fixed(u32 x) {
    if (x & 1u) x += 2u;
    return x + 7u;
}
u32 opaque_parity(u32 x) {
    if ((x * (x + 1u) & 1u) == 0u) return x + 7u;
    return x - 19u;
}
u64 opaque_parity64(u64 x) {
    if ((x * (x - 1u) % 2u) == 0u) return x + 7u;
    return x - 19u;
}
u32 opaque_bits(u32 x) {
    if (((x ^ x) | (x & ~x)) == 0u) return x + 7u;
    return x - 19u;
}
u32 opaque_fixed(u32 x) {
    u32 flag = 37u;
    if (x & 1u) x += 2u;
    if (flag == 37u) return x + 7u;
    return x - 19u;
}
u32 variable_predicate(u32 x) {
    if ((x * (x + 2u) & 1u) == 0u) return x + 7u;
    return x - 19u;
}
