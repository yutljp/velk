#include <stdint.h>

#define STORES(name, section_name) \
    __attribute__((noinline, section(section_name))) \
    uint32_t name(volatile uint8_t *bytes, uint32_t value) { \
        bytes[0] = value; \
        bytes[1] = value >> 8; \
        *(volatile uint16_t *)(bytes + 2) = value >> 16; \
        *(volatile uint32_t *)(bytes + 4) = value ^ 0x10203040; \
        *(volatile uint64_t *)(bytes + 8) = ((uint64_t)value << 32) | value; \
        return bytes[0] + bytes[1] + *(volatile uint16_t *)(bytes + 2) \
            + *(volatile uint32_t *)(bytes + 4) \
            + *(volatile uint64_t *)(bytes + 8); \
    }

STORES(text_stores, ".text")
STORES(init_stores, ".init")
STORES(fini_stores, ".fini")
STORES(hidden_stores, ".hidden")

__attribute__((noinline, section(".text")))
uint32_t call_hidden(volatile uint8_t *bytes, uint32_t value) {
    return hidden_stores(bytes, value) + 1;
}

extern volatile uint32_t executable_data[8];

uint32_t write_executable(uint32_t value) {
    executable_data[0] = value;
    return executable_data[1];
}

uint32_t read_executable(void) {
    return executable_data[0];
}
