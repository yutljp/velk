/* L1 — 分岐。早期 return・if/else・入れ子の三項。
 * 期待: if 文として構造化され、goto を残さない。 */
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
