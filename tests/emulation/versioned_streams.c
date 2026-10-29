#ifdef NATIVE
#include <stdio.h>
#else
typedef void FILE;
FILE *stdin __asm__("stdin_symbol_version");
FILE *stdout __asm__("stdout_symbol_version");
FILE *stderr __asm__("stderr_symbol_version");
extern void setbuf(FILE *, char *);
extern char *fgets(char *, int, FILE *);
extern int puts(const char *);
#endif

unsigned versioned_streams(void) {
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    char text[2];
    if (!fgets(text, 2, stdin)) return 0;
    puts(text);
    return (unsigned char)text[0];
}
#ifdef NATIVE
int main(void) { return versioned_streams() == 'Q' ? 0 : 1; }
#endif
