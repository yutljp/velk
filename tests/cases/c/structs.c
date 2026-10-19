/* Structures: nested fields, arrays of structures, by-value passing and return, unions, bitfields. */
struct point { int x; int y; };
struct rect { struct point min; struct point max; };
struct record { char tag; long value; short count; };
struct big { long a, b, c, d; };
union word { unsigned int u; float f; unsigned char bytes[4]; };
struct flags { unsigned ready : 1; unsigned mode : 3; unsigned level : 4; };

int rect_area(const struct rect *r) {
    return (r->max.x - r->min.x) * (r->max.y - r->min.y);
}

long record_total(const struct record *items, int n) {
    long total = 0;
    for (int i = 0; i < n; i++) total += items[i].value * items[i].count;
    return total;
}

struct point point_add(struct point a, struct point b) {
    struct point sum = { a.x + b.x, a.y + b.y };
    return sum;
}

struct big big_make(long seed) {
    struct big result = { seed, seed + 1, seed * 2, seed * 3 };
    return result;
}

long big_sum(struct big value) { return value.a + value.b + value.c + value.d; }

unsigned char word_low_byte(union word w) { return w.bytes[0]; }

unsigned flags_level(struct flags f) { return f.ready ? f.level : f.mode; }

void flags_set_mode(struct flags *f, unsigned mode) { f->mode = mode; }
