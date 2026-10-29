typedef unsigned int u32;
typedef unsigned long u64;

volatile u32 address_effect_value;

__attribute__((noinline)) u64 address_effect(u64 value) {
    address_effect_value = value;
    return value;
}

u32 address_add(u32 value) { return value + 7u; }

u32 address_store(u32 *pointer, u32 value) {
    *pointer = value + 3u;
    return *pointer;
}

u32 address_branch(u32 *pointer, u32 value) {
    if (value & 1u) *pointer = value + 3u;
    else *pointer = value ^ 85u;
    return *pointer + 7u;
}

u32 address_call(u32 value) {
    address_effect(value);
    return value + 7u;
}
