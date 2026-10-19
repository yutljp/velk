/* Control flow beyond single loops. */
int matrix_trace(const int *m, int n) {
    int total = 0;
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++)
            if (i == j) total += m[i * n + j];
    return total;
}

int cleanup_on_error(int a, int b, int *out) {
    int status = -1;
    if (a < 0) goto done;
    if (b == 0) goto done;
    *out = a / b;
    status = 0;
done:
    return status;
}

int fallthrough(int x) {
    int total = 0;
    switch (x) {
    case 0: total += 1; /* fall through */
    case 1: total += 2; /* fall through */
    case 2: total += 4; break;
    case 3: total = 8; break;
    default: total = -1;
    }
    return total;
}

int sparse(int x) {
    switch (x) {
    case 1: return 10;
    case 100: return 20;
    case 1000: return 30;
    case 10000: return 40;
    default: return 0;
    }
}

int short_circuit(const int *p, int n) { return p != 0 && n > 0 && (p[0] == 1 || p[n - 1] == 1); }

int skip_negatives(const int *p, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        if (p[i] < 0) continue;
        total += p[i];
    }
    return total;
}

int find_pair(const int *p, int n, int target) {
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (p[i] + p[j] == target) return i * n + j;
    return -1;
}
