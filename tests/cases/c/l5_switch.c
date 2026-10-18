/* L5 — 分岐表。密な表と疎な比較連鎖。
 * 値は規則性を崩してある(規則的だとコンパイラが算術に畳んでしまう)。
 * 期待: switch に戻り、各 case の値と本体が並ぶ。 */
volatile int g_sink;
/* Bodies that differ in shape force a jump table: bodies that differ only by
 * a constant are merged into one block plus a table of values, which the
 * decompiler reads as a single indexed load (a different, also correct,
 * shape). */
int dense(int x) {
    switch (x) {
    case 10: g_sink += 11; break;
    case 11: g_sink *= 3; break;
    case 12: g_sink ^= 77; break;
    case 13: g_sink -= 5; break;
    case 14: g_sink <<= 2; break;
    case 15: g_sink |= 9; break;
    case 16: g_sink += 21; break;
    case 17: g_sink *= 5; break;
    case 18: g_sink ^= 33; break;
    case 19: g_sink -= 13; break;
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
