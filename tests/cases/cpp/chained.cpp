// Data and function pointers shared by the chained and classic Mach-O fixtures.
extern "C" {
extern int imported_data[8];
int imported_function(int);
__attribute__((noinline, visibility("default"))) int local_function(int value) { return value + 7; }
__attribute__((visibility("default"))) extern int (*const function_table[])(int) = {local_function, imported_function};
__attribute__((visibility("default"))) int *const volatile data_pointer = imported_data + 3;
__attribute__((visibility("default"))) const char *const volatile text_pointer = "chained pointer string";
__attribute__((noinline, visibility("default"))) int table_call(unsigned index, int value) {
    return function_table[index & 1](value);
}
__attribute__((noinline, visibility("default"))) int data_read(void) { return *data_pointer; }
__attribute__((noinline, visibility("default"))) const char *text_read(void) { return text_pointer; }
}
