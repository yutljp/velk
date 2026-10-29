#ifdef NATIVE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#else
typedef __SIZE_TYPE__ size_t;
typedef struct FILE FILE;
extern void exit(int);
extern FILE *fopen(const char *, const char *);
extern int fclose(FILE *);
extern size_t fread(void *, size_t, size_t, FILE *);
extern size_t fwrite(const void *, size_t, size_t, FILE *);
extern char *fgets(char *, int, FILE *);
extern int fputs(const char *, FILE *);
extern int fflush(FILE *);
extern void setbuf(FILE *, char *);
extern int setvbuf(FILE *, char *, int, size_t);
extern int fileno(FILE *);
extern int feof(FILE *);
extern int ferror(FILE *);
#endif

unsigned read_file(void) {
    unsigned result = 0;
    unsigned char bytes[8] = {0};
    FILE *file = fopen("input", "rb");
    result += setvbuf(file, 0, 2, 0) == 0;
    result += fileno(file) >= 3;
    result += feof(file) == 0;
    result += ferror(file) == 0;
    if (fgets((char *)bytes, 4, file)) result += 16;
    for (unsigned i = 0; i < 3; ++i) result = result * 33 + bytes[i];
    result += (unsigned)fread(bytes, 2, 2, file) * 7;
    for (unsigned i = 0; i < 4; ++i) result = result * 33 + bytes[i];
    result += feof(file) != 0;
    while (fread(bytes, 1, 8, file)) {}
    result += (feof(file) != 0) * 3;
    result += (ferror(file) == 0) * 5;
    result += fclose(file) == 0;
    return result;
}

unsigned write_file(void) {
    FILE *file = fopen("output", "wb");
    setbuf(file, 0);
    unsigned result = setvbuf(file, 0, 0, 32) == 0;
    result += fwrite("ab\0c", 2, 2, file) == 2;
    result += fputs("\r\n", file) >= 0;
    result += fflush(file) == 0;
    result += fclose(file) == 0;
    file = fopen("output", "ab");
    result += fputs("tail", file) >= 0;
    result += fflush(0) == 0;
    result += fclose(file) == 0;
    return result;
}

unsigned update_file(void) {
    unsigned char bytes[4] = {0};
    FILE *file = fopen("input", "r+b");
    unsigned result = fwrite("XY", 1, 2, file) == 2;
    result += fflush(file) == 0;
    result += fread(bytes, 1, 3, file);
    result += (feof(file) != 0) * 8;
    result += fclose(file) == 0;
    return result + bytes[0] * 16 + bytes[1] * 256 + bytes[2] * 4096;
}

unsigned solve_file(void) {
    char line[4] = {0};
    unsigned char tail[2] = {0};
    FILE *file = fopen("input", "r");
    if (!fgets(line, 4, file)) { fclose(file); return 0; }
    if (fread(tail, 1, 2, file) != 2) { fclose(file); return 0; }
    fclose(file);
    return line[0] == 'O' && line[1] == 'K' && line[2] == '\n' && tail[0] == 0 && tail[1] == 255;
}

unsigned file_errors(void) {
    char bytes[2] = {0};
    FILE *file = fopen("input", "r");
    unsigned result = fwrite("x", 1, 1, file) == 0;
    result += (ferror(file) != 0) * 2;
    result += (feof(file) == 0) * 4;
    result += fclose(file) == 0;
    file = fopen("output", "w");
    result += fread(bytes, 1, 1, file) == 0;
    result += (ferror(file) != 0) * 16;
    result += (feof(file) == 0) * 32;
    result += fclose(file) == 0;
    return result;
}

unsigned invalid_file(void) { return (unsigned)feof((FILE *)0x1234); }
unsigned closed_file(void) { FILE *file = fopen("input", "r"); fclose(file); return (unsigned)ferror(file); }
unsigned unknown_file(void) { return fopen("missing", "r") != 0; }
unsigned unsupported_mode(void) { return fopen("input", "w+") != 0; }
unsigned unflushed_file(void) { FILE *file = fopen("output", "w"); return (unsigned)fwrite("pending", 1, 7, file); }

unsigned stream_boundaries(void);
unsigned append_existing(void);

#ifdef NATIVE
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    FILE *file = fopen("input", "wb");
    for (size_t i = 0; i < strlen(argv[2]); i += 2) {
        char pair[3] = {argv[2][i], argv[2][i + 1], 0};
        fputc((int)strtoul(pair, 0, 16), file);
    }
    fclose(file);
    file = fopen("output", "wb"); fclose(file);
    unsigned result;
    if (!strcmp(argv[1], "read_file")) result = read_file();
    else if (!strcmp(argv[1], "write_file")) result = write_file();
    else if (!strcmp(argv[1], "update_file")) result = update_file();
    else if (!strcmp(argv[1], "solve_file")) result = solve_file();
    else if (!strcmp(argv[1], "stream_boundaries")) result = stream_boundaries();
    else if (!strcmp(argv[1], "append_existing")) result = append_existing();
    else result = file_errors();
    printf("%u\n", result);
    for (unsigned i = 0; i < 2; ++i) {
        file = fopen(i ? "output" : "input", "rb");
        int byte;
        while ((byte = fgetc(file)) != EOF) printf("%02x", byte);
        fclose(file);
        puts("");
    }
    return 0;
}
#endif

unsigned stream_boundaries(void) {
    char bytes[4] = {'X', 'Y', 'Z', 0};
    FILE *file = fopen("input", "rb+");
    unsigned result = fread(0, 0, (size_t)-1, file) == 0;
    result += fwrite(0, (size_t)-1, 0, file) == 0;
    result += feof(file) == 0;
    result += ferror(file) == 0;
    result += fgets(bytes, 0, file) == 0;
    result += bytes[0] == 'X';
    result += fgets(bytes, -1, file) == 0;
    result += bytes[0] == 'X';
    result += fgets(bytes, 1, file) == bytes;
    result += bytes[0] == 0;
    result += feof(file) == 0;
    result += setvbuf(file, 0, 12345, 0) != 0;
    result += ferror(file) == 0;
    result += fclose(file) == 0;
    return result;
}

unsigned append_existing(void) {
    FILE *file = fopen("input", "a");
    unsigned result = fwrite("Z", 1, 1, file) == 1;
    result += fclose(file) == 0;
    return result;
}

#ifndef NATIVE
extern int getchar(void);
#endif
unsigned combined_inputs(void) {
    unsigned char byte = 0;
    FILE *file = fopen("input", "r");
    if (fread(&byte, 1, 1, file) != 1) { fclose(file); return 0; }
    fclose(file);
    file = fopen("output", "w");
    fwrite(&byte, 1, 1, file);
    fclose(file);
    return byte == 'Q' && getchar() == 'R';
}

unsigned output_assignment(void) {
    unsigned char byte = (unsigned char)~getchar();
    FILE *file = fopen("output", "w");
    unsigned result = fwrite(&byte, 1, 1, file) == 1;
    fclose(file);
    return result;
}

unsigned caller_buffer(void) {
    char buffer[8192];
    FILE *file = fopen("output", "w");
    setbuf(file, buffer);
    return 1;
}

unsigned exit_file(void) {
    FILE *file = fopen("output", "w");
    fwrite("Q", 1, 1, file);
    exit(3);
    return 99;
}
