// A function whose failure path GCC moves into a cold fragment with a
// frame description of its own, reached by a jump from the hot part.
#include <stdio.h>
#include <stdlib.h>

struct item {
    int key;
    int value;
    char name[16];
};

__attribute__((noinline)) int lookup(struct item *items, int count, int key) {
    for (int i = 0; i < count; i++) {
        if (items[i].key == key)
            return items[i].value;
    }
    char buffer[64];
    snprintf(buffer, sizeof buffer, "missing key %d among %d", key, count);
    fputs(buffer, stderr);
    for (int i = 0; i < count; i++)
        fprintf(stderr, "  %s=%d\n", items[i].name, items[i].value);
    abort();
}

int main(int argc, char **argv) {
    struct item items[2] = {{1, 10, "one"}, {2, 20, "two"}};
    (void)argv;
    return lookup(items, 2, argc);
}
