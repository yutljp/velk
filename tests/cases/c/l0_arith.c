/* L0 — arithmetic, selection, signedness. The smallest unit of recovery.
 * Expected: expressions survive as written (no folded constants, no stray masks). */
int add3(int a, int b, int c) { return a + b + c; }
int scale(int x) { return x * 7 + 3; }
int pick(int a, int b) { return a > b ? a : b; }
int negate(int x) { return -x; }
