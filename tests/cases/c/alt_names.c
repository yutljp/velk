int alt_sum3(int a, int b, int c) { return a + b + c; }
int alt_helper(int x) {
    int r = 0;
    for (int i = 0; i < x; i++) r += i * i;
    return r;
}
