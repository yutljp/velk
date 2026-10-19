/* L6 — ABI edge cases: tail calls (direct/indirect), varargs, 6 arguments, 64-bit.
 * Expected: tail calls are treated as function boundaries; varargs are annotated as va_list. */
typedef int (*fn)(int);

__attribute__((noinline)) int tail_target(int x) {
    volatile int y = x * 3;
    return y + 1;
}
__attribute__((noinline)) int tail_direct(int x) { return tail_target(x + 2); }
__attribute__((noinline)) int tail_indirect(fn f, int x) { return f(x + 1); }

int six_args(int a, int b, int c, int d, int e, int f) {
    return a + b + c + d + e + f;
}
unsigned long long wide_add(unsigned long long a, unsigned long long b) {
    return a + b;
}
