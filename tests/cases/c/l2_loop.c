/* L2 — loops: while / do-while / for, break and continue.
 * Each iteration writes to a volatile so the optimizer keeps the loop shape.
 * Expected: structured as while and do{}while, with break/continue visible. */
volatile int sink;

int sum_while(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) { s += i; sink = s; }
    return s;
}
int count_down(int n) {
    int c = 0;
    do { c++; n--; sink = c; } while (n > 0);
    return c;
}
int sum_skip_odd(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        if ((i & 1) == 0) continue;
        s += i;
        sink = s;
    }
    return s;
}
int find_first(const int *p, int n, int v) {
    for (int i = 0; i < n; i++)
        if (p[i] == v) return i;
    return -1;
}
