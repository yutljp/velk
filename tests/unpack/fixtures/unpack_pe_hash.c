// The start of a packed Windows program that names no import of the
// packed part: it finds the function among the exports of its library by
// a hash of the name.
#include <stdint.h>

__declspec(dllimport) void *__stdcall LoadLibraryA(const char *name);
__declspec(dllimport) int __stdcall VirtualProtect(void *address, uintptr_t size,
                                                   uint32_t protection, uint32_t *previous);

extern unsigned char payload_start[];
extern unsigned char payload_end[];
extern void *payload_imports[];
int original(void);

// Of "GetLogicalDrives": each byte added after a rotation right by 13.
#define WANTED 0x14c22b19u

static uint32_t word(const unsigned char *at) { return *(const uint32_t *)at; }

static void *find(const unsigned char *base, uint32_t wanted) {
    const unsigned char *optional = base + word(base + 0x3c) + 24;
    const unsigned char *exports =
        base + word(optional + (*(const uint16_t *)optional == 0x20b ? 112 : 96));
    const uint32_t *functions = (const uint32_t *)(base + word(exports + 28));
    const uint32_t *names = (const uint32_t *)(base + word(exports + 32));
    const uint16_t *ordinals = (const uint16_t *)(base + word(exports + 36));
    for (uint32_t index = 0; index != word(exports + 24); index++) {
        uint32_t hash = 0;
        for (const unsigned char *name = base + names[index]; *name; name++) {
            hash = (hash >> 13 | hash << 19) + *name;
        }
        if (hash == wanted) {
            return (void *)(base + functions[ordinals[index]]);
        }
    }
    return 0;
}

int entry(void) {
    uint32_t previous;
    VirtualProtect(payload_start, (uintptr_t)(payload_end - payload_start), 0x40, &previous);
    for (unsigned char *byte = payload_start; byte != payload_end; byte++) {
        *byte ^= 0x5a;
    }
    payload_imports[3] = find(LoadLibraryA("kernel32.dll"), WANTED);
    if (!payload_imports[3]) {
        __builtin_trap();
    }
    return original();
}
