__attribute__((noinline)) int tail_one(int x) { volatile int y = x * 3; return y + 1; }
__attribute__((noinline)) int tail_two(int x) { return tail_one(x + 2); }
__attribute__((noinline)) int tail_three(int x) { volatile int z = x - 7; return z; }
