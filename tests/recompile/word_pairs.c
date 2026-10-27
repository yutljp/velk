typedef unsigned short u16;
typedef unsigned int u32;
typedef signed int i32;
typedef unsigned long long u64;
typedef signed long long i64;

__attribute__((noinline)) i32 stack_callee(u16 a, u64 b) { return a + (i32)b; }
i32 stack_caller(i32 y) { return stack_callee(7, (u64)(i64)y << 3); }

i32 g_a;
__attribute__((noinline)) u64 g(i32 x) {
    g_a += x;
    return ((u64)g_a << 32) | (u32)(x * 7);
}
__attribute__((noinline)) i32 h(u64 a, i32 b) {
    return (i32)(a >> 32) * 3 + (i32)a + b;
}
i32 f(i32 x) { u64 r = g(x); return h(r, x) + (i32)(r >> 32); }

__attribute__((noinline)) i64 return_callee(u16 a, u64 b) { return a + b; }
i64 return_caller(i32 y) { return return_callee(1, (u64)(i64)y << 3); }
u32 observe_return(i32 y) { return (u64)return_caller(y) >> 32; }
__attribute__((noinline)) i64 multiply_callee(u64 b) { return b * 3 + 5; }
i64 multiply_caller(i32 y) { return multiply_callee((u64)(i64)y ^ 7); }
u32 observe_multiply(i32 y) { return (u64)multiply_caller(y) >> 32; }

__attribute__((noinline)) u32 narrow_sum(u64 a, u64 b) { return (u32)(a + b); }
u32 use_narrow(u64 a, u64 b) { return narrow_sum(a, b); }

__attribute__((noinline)) u32 narrow_live_high(u32 x) {
#if defined(__i386__)
    u64 wide = (u64)x * 0x100000001ULL;
    __asm__ volatile ("" : "+A" (wide));
    return (u32)wide;
#elif defined(__arm__)
    register u32 high __asm__("r1") = x;
    __asm__ volatile ("" : "+r" (high));
    return x;
#else
    return x;
#endif
}
u32 use_live_high(u32 x) { return narrow_live_high(x); }

__attribute__((noinline)) u32 preserve_high(u32 x) { return x + 1; }
u32 preserved_high_caller(u32 x, u32 y) {
#if defined(__arm__)
    register u32 low __asm__("r0") = x;
    register u32 high __asm__("r1") = y;
    __asm__ volatile ("bl preserve_high" : "+r" (low), "+r" (high) : : "lr", "cc", "memory");
    return low + high;
#else
    return preserve_high(x) + y;
#endif
}
