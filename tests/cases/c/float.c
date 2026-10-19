/* Floating point: recorded so future support can be measured. */
double average(const double *values, int n) {
    double total = 0.0;
    for (int i = 0; i < n; i++) total += values[i];
    return n > 0 ? total / n : 0.0;
}

float lerp(float a, float b, float t) { return a + (b - a) * t; }

int truncate_to_int(double x) { return (int)x; }

double widen(float x) { return (double)x * 2.0; }

int compare_doubles(double a, double b) { return a < b ? -1 : (a > b ? 1 : 0); }
