typedef unsigned int u32;
#ifndef STATE_QUALIFIER
#define STATE_QUALIFIER
#endif

u32 original_line(u32 x) { return (x + 3u) ^ 85u; }
u32 flattened_line(u32 x) {
    STATE_QUALIFIER u32 state = 11u;
    for (;;) {
        switch (state) {
        case 11u: x += 3u; state = 29u; break;
        case 29u: x ^= 85u; state = 47u; break;
        case 47u: return x;
        default: return 0u;
        }
    }
}
u32 original_branch(u32 x) {
    if (x & 1u) x += 3u; else x ^= 85u;
    return x + 7u;
}
u32 flattened_branch(u32 x) {
    STATE_QUALIFIER u32 state = 11u;
    for (;;) {
        switch (state) {
        case 11u: state = (x & 1u) ? 29u : 47u; break;
        case 29u: x += 3u; state = 61u; break;
        case 47u: x ^= 85u; state = 61u; break;
        case 61u: return x + 7u;
        default: return 0u;
        }
    }
}
u32 original_loop(u32 x) {
    u32 sum = 0u;
    for (u32 i = 0u; i < (x & 15u); ++i) sum += i;
    return sum;
}
u32 flattened_loop(u32 x) {
    STATE_QUALIFIER u32 state = 11u;
    u32 sum = 0u, i = 0u;
    for (;;) {
        switch (state) {
        case 11u: state = i < (x & 15u) ? 29u : 47u; break;
        case 29u: sum += i; ++i; state = 11u; break;
        case 47u: return sum;
        default: return 0u;
        }
    }
}
u32 variable_transition(u32 x) {
    STATE_QUALIFIER u32 state = 11u;
    for (;;) {
        switch (state) {
        case 11u: state = x; break;
        case 29u: return x + 3u;
        default: return x;
        }
    }
}
