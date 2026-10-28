extern __attribute__((visibility("default"))) int vprintf(const char *, __builtin_va_list);
__attribute__((noinline)) int forward_format(const char *format, __builtin_va_list args) {
    return vprintf(format, args);
}
#define HELPER(n) __attribute__((noinline)) int helper##n(int x) { return x + n + 1; }
HELPER(0)
HELPER(1)
HELPER(2)
HELPER(3)
HELPER(4)
HELPER(5)
HELPER(6)
HELPER(7)
HELPER(8)
__attribute__((noinline)) unsigned long pointer_bits(unsigned long x) { return x + 1; }
int main(int argc, char **argv, char **envp) {
    (void)argv;
    
    int sum = helper0(argc) + helper1(argc) + helper2(argc) + helper3(argc)
        + helper4(argc) + helper5(argc) + helper6(argc) + helper7(argc) + helper8(argc);
    return sum + pointer_bits((unsigned long)envp);
}
