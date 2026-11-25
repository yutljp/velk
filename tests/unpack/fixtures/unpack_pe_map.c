// The start of a program that carries another one: it maps the headers
// and sections of that file into memory it allocates, moves its addresses
// to where it landed, resolves its imports and runs it there.
#include <stdint.h>

__declspec(dllimport) void *__stdcall LoadLibraryA(const char *name);
__declspec(dllimport) void *__stdcall GetProcAddress(void *module, const char *name);
__declspec(dllimport) void *__stdcall VirtualAlloc(void *address, uintptr_t size, uint32_t type,
                                                   uint32_t protection);

extern const unsigned char inner_image[];

static uint32_t half(const unsigned char *at) { return *(const uint16_t *)at; }
static uint32_t word(const unsigned char *at) { return *(const uint32_t *)at; }

static void copy(unsigned char *to, const unsigned char *from, uint32_t count) {
    while (count--) {
        *to++ = *from++;
    }
}

int entry(void) {
    const unsigned char *file = inner_image;
    const unsigned char *header = file + word(file + 0x3c);
    const unsigned char *optional = header + 24;
    int wide = half(optional) == 0x20b;
    const unsigned char *directories = optional + (wide ? 112 : 96);
    uintptr_t preferred = wide ? (uintptr_t) * (const uint64_t *)(optional + 24)
                               : (uintptr_t)word(optional + 28);
    unsigned char *base = VirtualAlloc(0, word(optional + 56), 0x3000, 0x40);
    copy(base, file, word(optional + 60));
    const unsigned char *section = optional + half(header + 20);
    for (uint32_t index = 0; index != half(header + 6); index++, section += 40) {
        uint32_t size = word(section + 16) < word(section + 8) ? word(section + 16)
                                                               : word(section + 8);
        copy(base + word(section + 12), file + word(section + 20), size);
    }

    uintptr_t moved = (uintptr_t)base - preferred;
    unsigned char *block = base + word(directories + 5 * 8);
    unsigned char *last = block + word(directories + 5 * 8 + 4);
    while (block != last) {
        unsigned char *page = base + word(block);
        for (uint32_t at = 8; at != word(block + 4); at += 2) {
            uint32_t entry = half(block + at);
            if (entry >> 12 == 3) {
                *(uint32_t *)(page + (entry & 0xfff)) += (uint32_t)moved;
            } else if (entry >> 12 == 10) {
                *(uint64_t *)(page + (entry & 0xfff)) += moved;
            }
        }
        block += word(block + 4);
    }

    for (unsigned char *import = base + word(directories + 8); word(import + 12); import += 20) {
        void *module = LoadLibraryA((const char *)base + word(import + 12));
        uintptr_t *name = (uintptr_t *)(base + word(import));
        uintptr_t *slot = (uintptr_t *)(base + word(import + 16));
        for (; *name; name++, slot++) {
            *slot = (uintptr_t)GetProcAddress(module, (const char *)base + *name + 2);
        }
    }
    return ((int (*)(void))(base + word(optional + 16)))();
}
