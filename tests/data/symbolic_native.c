#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
extern long integer_value(const char *, unsigned);
extern unsigned long integer_end(const char *, unsigned);
extern unsigned case_value(unsigned);
extern int scan_stream(void), scan_stack(void);
extern int scan_decimal(void), scan_unsigned(void), scan_hex(void), scan_text(void);
extern int scan_signed(void), scan_signed_min(void), scan_invalid(void), scan_eof(void), scan_unsigned_sign(void);
extern int scan_many(void);
extern int scan_relations(const char *);
extern int scan_characters(void), scan_string(void), line_compare(void), allocated_line(void);
extern int integer_check(void), integer_hex(void), copy_check(void), output_check(void);
extern int bound_descriptor(void);
extern int argv_one(int, char **), argv_two(int, char **), argv_three(int, char **);
int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "scan_relations") == 0)
        return scan_relations(argv[2]) == 1 ? 0 : 1;
    if (argc >= 3) {
        if (strcmp(argv[1], "argv_one") == 0) return !argv_one(argc-2, argv+2);
        if (strcmp(argv[1], "argv_two") == 0) return !argv_two(argc-2, argv+2);
        if (strcmp(argv[1], "argv_three") == 0) return !argv_three(argc-2, argv+2);
    }
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
    if (strcmp(argv[1], "tail_getchar") == 0) return getchar() == EOF ? 0 : 1;
    const struct { const char *name; int (*function)(void); } checks[] = {
        {"scan_stream", scan_stream}, {"scan_stack", scan_stack},
        {"scan_decimal", scan_decimal}, {"scan_unsigned", scan_unsigned},
        {"scan_signed", scan_signed}, {"scan_signed_min", scan_signed_min}, {"scan_invalid", scan_invalid},
        {"scan_eof", scan_eof}, {"scan_unsigned_sign", scan_unsigned_sign},
        {"scan_many", scan_many},
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
