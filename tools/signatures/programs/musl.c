#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
static int compare(const void *a, const void *b) { return *(const int *)a - *(const int *)b; }
int main(int argc, char **argv) {
    char text[128]; int values[] = {9, 1, 4, 3, 2};
    const char *input = argc > 1 ? argv[1] : "42.25";
    qsort(values, 5, sizeof(int), compare);
    char *copy = strdup(input); if (!copy) return 1;
    snprintf(text, sizeof(text), "%s:%ld:%.2f", copy, strtol(copy, 0, 10), sqrt(strtod(copy, 0)));
    int result = puts(text) < 0 || memcmp(values, values + 1, sizeof(int)) >= 0 || !isdigit((unsigned char)copy[0]);
    free(copy); return result;
}
