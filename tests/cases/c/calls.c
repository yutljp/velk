/* Calls: function pointers, tables, recursion, stack arguments, varargs.
   Inputs are expected to stay in range; signed overflow is not exercised. */
typedef int (*unary)(int);

int twice(int x) { return x * 2; }
int square(int x) { return x * x; }

unary pick_op(int which) { return which ? square : twice; }

static const unary table[3] = { twice, square, twice };

int apply_table(unsigned index, int x) { return table[index % 3](x); }

int apply_pointer(unary f, int x) { return f(x) + 1; }

int factorial(int n) { return n <= 1 ? 1 : n * factorial(n - 1); }

int is_even(int n);
int is_odd(int n) { return n == 0 ? 0 : is_even(n - 1); }
int is_even(int n) { return n == 0 ? 1 : is_odd(n - 1); }

long sum9(long a, long b, long c, long d, long e, long f, long g, long h, long i) {
    return a + b + c + d + e + f + g + h + i;
}

long call_sum9(long x) { return sum9(x, 1, 2, 3, 4, 5, 6, 7, 8); }

int sum_varargs(int count, ...) {
    __builtin_va_list args;
    __builtin_va_start(args, count);
    int total = 0;
    for (int i = 0; i < count; i++) total += __builtin_va_arg(args, int);
    __builtin_va_end(args);
    return total;
}
