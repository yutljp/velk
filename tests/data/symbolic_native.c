#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
extern long integer_value(const char *, unsigned);
extern unsigned long integer_end(const char *, unsigned);
extern unsigned case_value(unsigned);
extern int scan_stream(void), scan_stack(void);
extern int scan_decimal(void), scan_unsigned(void), scan_hex(void), scan_text(void);
extern int scan_characters(void), scan_string(void), line_compare(void), allocated_line(void);
extern int integer_check(void), integer_hex(void), copy_check(void), output_check(void);
extern int bound_descriptor(void);
int main(int argc, char **argv) {
    if (argc == 4) {
        unsigned base = (unsigned)strtoul(argv[3], 0, 10);
        unsigned long value;
        if (strcmp(argv[1], "integer_value") == 0) value = (unsigned long)integer_value(argv[2], base);
        else if (strcmp(argv[1], "integer_end") == 0) value = integer_end(argv[2], base);
        else if (strcmp(argv[1], "case_value") == 0) value = case_value((unsigned)strtoul(argv[2], 0, 10));
        else return 2;
        printf("0x%lx", value);
        return 0;
    }
    if (argc != 2) return 2;
    const struct { const char *name; int (*function)(void); } checks[] = {
        {"scan_stream", scan_stream}, {"scan_stack", scan_stack},
        {"scan_decimal", scan_decimal}, {"scan_unsigned", scan_unsigned},
        {"scan_hex", scan_hex}, {"scan_text", scan_text},
        {"scan_characters", scan_characters}, {"scan_string", scan_string},
        {"line_compare", line_compare}, {"allocated_line", allocated_line},
        {"integer_check", integer_check}, {"integer_hex", integer_hex},
        {"copy_check", copy_check}, {"output_check", output_check},
        {"bound_descriptor", bound_descriptor}
    };
    if (dup2(0, 7) < 0) return 2;
    for (unsigned i = 0; i < sizeof(checks)/sizeof(checks[0]); ++i)
        if (strcmp(argv[1], checks[i].name) == 0) return checks[i].function() == 1 ? 0 : 1;
    return 2;
}
