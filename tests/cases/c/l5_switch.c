/* L5 — 分岐表。密な表と疎な比較連鎖。
 * 値は規則性を崩してある(規則的だとコンパイラが算術に畳んでしまう)。
 * 期待: switch に戻り、各 case の値と本体が並ぶ。 */
volatile int g_sink;
/* Distinct callees force a jump table, and sixteen dense cases are enough
 * for clang 18 as well (with fewer it prefers a compare tree). Bodies that
 * differ only by a constant are merged into one block plus a table of
 * values, which the decompiler reads as a single indexed load. */
static void c0(void) { g_sink += 11; }
static void c1(void) { g_sink ^= 18; }
static void c2(void) { g_sink -= 25; }
static void c3(void) { g_sink |= 32; }
static void c4(void) { g_sink += 39; }
static void c5(void) { g_sink ^= 46; }
static void c6(void) { g_sink -= 53; }
static void c7(void) { g_sink |= 60; }
static void c8(void) { g_sink += 67; }
static void c9(void) { g_sink ^= 74; }
static void c10(void) { g_sink -= 81; }
static void c11(void) { g_sink |= 88; }
static void c12(void) { g_sink += 95; }
static void c13(void) { g_sink ^= 102; }
static void c14(void) { g_sink -= 109; }
static void c15(void) { g_sink |= 116; }
int dense(int x) {
    switch (x) {
    case 10: c0(); break;
    case 11: c1(); break;
    case 12: c2(); break;
    case 13: c3(); break;
    case 14: c4(); break;
    case 15: c5(); break;
    case 16: c6(); break;
    case 17: c7(); break;
    case 18: c8(); break;
    case 19: c9(); break;
    case 20: c10(); break;
    case 21: c11(); break;
    case 22: c12(); break;
    case 23: c13(); break;
    case 24: c14(); break;
    case 25: c15(); break;
    default: g_sink = 0; break;
    }
    return g_sink;
}
int sparse(int x) {
    switch (x) {
    case 1: return 100;
    case 50: return 7;
    case 300: return 300;
    default: return -1;
    }
}
