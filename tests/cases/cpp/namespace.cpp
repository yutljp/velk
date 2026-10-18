namespace ns {
__attribute__((noinline)) int add(int a, int b) { return a + b; }
__attribute__((noinline)) int mul(int a, int b) { return a * b; }
}
int use(int x) { return ns::add(x, ns::mul(x, 2)); }
