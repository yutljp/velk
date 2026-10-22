struct outer {
    struct inner {
        unsigned head;
    } first;
    int *next;
    short count;
};

int read_outer(const struct outer *p) {
    return p->first.head + *p->next + p->count;
}
