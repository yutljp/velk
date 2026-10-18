/* L4 — メモリ。配列・構造体メンバ・グローバル・文字列リテラル。
 * 期待: メンバ名/配列添字/グローバル名/文字列参照が出る。 */
struct point { int x; int y; };

int point_dot(const struct point *a, const struct point *b) {
    return a->x * b->x + a->y * b->y;
}
int array_sum(const int *a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += a[i];
    return s;
}
int g_counter;
void bump(void) { g_counter++; }

const char *banner = "velk ladder";
int banner_first(void) { return banner[0]; }
