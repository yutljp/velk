/* L6 — ABI の端。テールコール(直接/間接)・可変長引数・6 引数・64bit。
 * 期待: テールコールは境界として扱われ、可変長は va_list として注記される。 */
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
