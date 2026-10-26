#define KEEP __attribute__((noinline))
volatile int total_before = 41;
KEEP int stable(int x) { return x * 7 + 19; }
KEEP int helper(int x) { return x ^ 339; }
KEEP int renamed_before(int x) { return x * 13 + 29; }
KEEP int edited(int x) { return x + 31; }
KEEP int route_before(int x) {
    if (x > 9) return stable(x) + helper(x) + 101;
    return stable(x) - helper(x) + 101;
}
KEEP int read_total(int x) { return total_before + x; }
KEEP const char *message_before(void) { return "comparison message"; }
KEEP int removed(int x) { return x / 17; }
KEEP int folded(int x) { return x + 67; }
KEEP int ambiguous_a(int x) { return x * 53; }
KEEP int ambiguous_b(int x) { return x * 53; }
int entry(int x) {
    return stable(x) + helper(x) + renamed_before(x) + edited(x) + route_before(x)
        + read_total(x) + message_before()[0] + removed(x) + folded(x)
        + ambiguous_a(x) + ambiguous_b(x);
}
