int sum3(int a, int b, int c) { return a + b + c; }
int helper(int x) {
    int r = 0;
    for (int i = 0; i < x; i++) r += i * i;
    return r;
}
struct pair { int a; int b; };
int pair_sum(const struct pair *p) { return p->a + p->b; }
int sum_arr(const int *p, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) total += p[i];
    return total;
}
