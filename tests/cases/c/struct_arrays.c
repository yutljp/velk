/* Arrays of structures: an index scaled by the element size, plus a field's offset. */
struct item { long key; int count; short kind; };
struct cell { int x; int y; int z; };

int item_weight(const struct item *items, int i) { return items[i].kind * items[i].count; }

void cell_set(struct cell *cells, long i, int v) {
    cells[i].x = v;
    cells[i].z = v + 1;
}

long item_last_key(const struct item *items, int n) {
    long key = 0;
    for (int i = 0; i < n; i++)
        if (items[i].count > 0) key = items[i].key;
    return key;
}
