#define KEEP __attribute__((noinline))
volatile int total_after = 41;
KEEP int stable(int x) { return x * 7 + 19; }
KEEP int helper(int x) { return x ^ 339; }
KEEP int renamed_after(int x) { return x * 13 + 29; }
KEEP int edited(int x) { return x + 37; }
KEEP int route_after(int x) {
    if (x > 3) return stable(x) + helper(x) + 101;
    return stable(x) - helper(x) + 101;
}
KEEP int read_total(int x) { return total_after + x; }
KEEP const char *message_after(void) { return "comparison message"; }
KEEP int added(int x) { return x % 23; }
static __attribute__((always_inline)) inline int folded(int x) { return x + 67; }
KEEP int ambiguous_a(int x) { return x * 53; }
KEEP int ambiguous_b(int x) { return x * 53; }
int entry(int x) {
    return stable(x) + helper(x) + renamed_after(x) + edited(x) + route_after(x)
        + read_total(x) + message_after()[0] + added(x) + folded(x)
        + ambiguous_a(x) + ambiguous_b(x);
}
