#include <stdint.h>

volatile int state;

__attribute__((noinline)) void effect(void) {
    state = 0;
}

__attribute__((noinline)) uint32_t final_byte(int32_t value) {
    effect();
    return (int8_t)value;
}

__attribute__((noinline)) void discard(int32_t value) {
    final_byte(value);
}

int main(int argc, char **argv) {
    discard(argc);
    return state;
}
