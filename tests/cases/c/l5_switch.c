/* L5 — 分岐表。密な表と疎な比較連鎖。
 * 値は規則性を崩してある(規則的だとコンパイラが算術に畳んでしまう)。
 * 期待: switch に戻り、各 case の値と本体が並ぶ。 */
volatile int g_sink;
/* Distinct callees force a jump table: a compiler keeps a table of code
 * addresses when the bodies are not arithmetic on a common value (bodies that
 * differ only by a constant become one block plus a table of values, which
 * the decompiler reads as a single indexed load). */
static void c0(void) { g_sink += 11; }
static void c1(void) { g_sink ^= 3; }
static void c2(void) { g_sink -= 77; }
static void c3(void) { g_sink <<= 1; }
static void c4(void) { g_sink |= 5; }
static void c5(void) { g_sink *= 7; }
static void c6(void) { g_sink += 21; }
static void c7(void) { g_sink ^= 33; }
static void c8(void) { g_sink -= 13; }
static void c9(void) { g_sink += 2; }
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
