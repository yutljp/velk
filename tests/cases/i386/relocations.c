int add_bias(int x) { return x + 7; }
int (*selected)(int) = add_bias;
static int bias = 11;
int *bias_pointer = &bias;
extern int abs(int);
int imported(int x) { return abs(x) + 3; }

int via_plt(int x) { return add_bias(x); }
