volatile int g;

__attribute__((noinline)) void a(void) { g += 1; }
__attribute__((noinline)) void b(void) { g *= 3; }
__attribute__((noinline)) void c(void) { g ^= 7; }
__attribute__((noinline)) void d(void) { g -= 9; }
__attribute__((noinline)) void e(void) { g <<= 1; }
__attribute__((noinline)) void f(void) { g |= 5; }

__attribute__((noinline)) int sw(unsigned x) {
    switch (x) {
    case 5: a(); break;
    case 6: b(); break;
    case 7: c(); break;
    case 8: d(); break;
    case 9: e(); break;
    case 10: f(); break;
    default: g = 0;
    }
    return g;
}

int main(void) { return sw((unsigned)g); }
