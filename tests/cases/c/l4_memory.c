/* L4 — memory: arrays, struct members, globals, string literals.
 * Expected: member names, array indices, global names and string references appear. */
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
