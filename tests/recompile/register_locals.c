#include <stdint.h>

uint8_t byte_state;
extern void effect(void);

__attribute__((noinline)) int32_t decrement_byte(unsigned count) {
    do {
        for (unsigned i = 0; i < count; ++i)
            effect();
        --byte_state;
    } while (!(byte_state & 0x80));
    return (int8_t)byte_state;
}
