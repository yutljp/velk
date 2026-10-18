int reg_add(int a, int b) { return a + b; }
int reg_mul(int a, int b) { return a * b; }
int reg_sign(signed char a, short b) { return a + b; }
int reg_max(int a, int b) { return a > b ? a : b; }
int reg_negative(int x) { return x < 0; }
long reg_abs(long x) { return x < 0 ? -x : x; }
const char *kMsg = "velk-ref-string";
int msg_first(void) { return kMsg[1]; }
int reg_div(int a, int b) { return a / b; }
int reg_mod(int a, int b) { return a % b; }
void entry(void) {
    volatile int x = reg_add(2, 3);
    volatile int y = reg_mul(x, 7);
    (void)y;
}
