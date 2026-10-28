__attribute__((noinline)) void success(void) { puts("success"); }
__attribute__((noinline)) void failure(void) { puts("failure"); }
int main(int argc, char **argv) {
    unsigned char s[5] = {0};
#ifdef INPUT_ARGV
    if (argc != 2) return 2;
    const unsigned char *input = (const unsigned char *)argv[1];
#else
    (void)argc; (void)argv;
#ifdef INPUT_SCANF
    if (scanf("%4s", s) != 1) return 2;
#elif defined(INPUT_FGETS)
    if (!fgets((char *)s, 5, stdin)) return 2;
#else
    if (read(0, s, 4) != 4) return 2;
#endif
    const unsigned char *input = s;
#endif
    if (check(input)) { success(); return 0; }
    failure(); return 1;
}
