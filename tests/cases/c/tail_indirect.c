typedef int (*hook)(int);
__attribute__((noinline)) int via_ptr(hook f, int x) { return f(x + 1); }
__attribute__((noinline)) int after_ptr(int x) { volatile int y = x + 5; return y; }
