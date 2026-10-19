/* Memory access patterns. */
void copy_bytes(unsigned char *dst, const unsigned char *src, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) dst[i] = src[i];
}

void fill_bytes(unsigned char *dst, unsigned char value, unsigned long n) {
    for (unsigned long i = 0; i < n; i++) dst[i] = value;
}

unsigned long string_length(const char *s) {
    unsigned long n = 0;
    while (s[n]) n++;
    return n;
}

int grid[4][8];

int grid_get(int row, int col) { return grid[row & 3][col & 7]; }

void grid_set(int row, int col, int value) { grid[row & 3][col & 7] = value; }

long pointer_distance(const int *begin, const int *end) { return end - begin; }

int read_volatile(volatile int *p) {
    int a = *p;
    int b = *p;
    return a + b;
}

void swap_ints(int *a, int *b) {
    int t = *a;
    *a = *b;
    *b = t;
}
