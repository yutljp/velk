/* L1 — branches: early return, if/else, nested ternaries.
 * Expected: structured as if statements with no leftover goto. */
int classify(int x) {
    if (x < 0) return -1;
    if (x == 0) return 0;
    return 1;
}
int clamp(int x, int lo, int hi) {
    if (x < lo) return lo;
    if (x > hi) return hi;
    return x;
}
int sign_of(int x) { return x > 0 ? 1 : (x < 0 ? -1 : 0); }
