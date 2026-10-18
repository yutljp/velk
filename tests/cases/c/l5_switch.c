/* L5 — 分岐表。密な表と疎な比較連鎖。
 * 値は規則性を崩してある(規則的だとコンパイラが算術に畳んでしまう)。
 * 期待: switch に戻り、各 case の値と本体が並ぶ。 */
int dense(int x) {
    switch (x) {
    case 10: return 11;
    case 11: return 3;
    case 12: return 77;
    case 13: return 5;
    case 14: return 91;
    default: return 0;
    }
}
int sparse(int x) {
    switch (x) {
    case 1: return 100;
    case 50: return 7;
    case 300: return 300;
    default: return -1;
    }
}
