// A shared library whose dynamic relocations fill a function pointer and a
// global offset table slot. The static functions take places in the full
// symbol table that the dynamic one leaves out, so the two number apart.
static int hidden_a(int x) { return x - 3; }
static int hidden_b(int x) { return x ^ 5; }

int helper_one(int x) { return hidden_a(x) + 1; }
int helper_two(int x) { return hidden_b(x) * 2; }
int target(int x) { return x * 7; }

int (*table_ptr)(int) = target;

int use_ptr(int a) { return table_ptr(a); }
