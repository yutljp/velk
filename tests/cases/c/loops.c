int count_bits(unsigned x) {
    int n = 0;
    while (x) {
        n += x & 1;
        x >>= 1;
    }
    return n;
}
int sum_until(int limit) {
    int total = 0;
    for (int i = 1; i <= limit; i++) total += i;
    return total;
}
int sum_till_neg(const int *p, int n) {
    int total = 0;
    int i = 0;
    while (i < n) {
        int v = p[i];
        if (v < 0) break;
        total += v;
        i++;
    }
    return total;
}
int sum_until_zero(const int *p, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        if (p[i] == 0) break;
        if (p[i] < 0) continue;
        total += p[i];
    }
    return total;
}
