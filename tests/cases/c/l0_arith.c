/* L0 — 算術・選択・符号。復元の最小単位。
 * 期待: 式がそのまま残る(定数畳み込み・マスク混入なし)。 */
int add3(int a, int b, int c) { return a + b + c; }
int scale(int x) { return x * 7 + 3; }
int pick(int a, int b) { return a > b ? a : b; }
int negate(int x) { return -x; }
