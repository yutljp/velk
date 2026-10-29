typedef unsigned int u32;
typedef __SIZE_TYPE__ usize;
typedef int (*Function)(int);
struct Export { const char *name; Function address; };
struct Module { struct Module *next; const struct Export *exports; usize count; };
struct Module *modules;

#define NOINLINE __attribute__((noinline))
NOINLINE u32 ror13(const char *name) {
    u32 hash = 0;
    while (*name) { hash = (hash >> 13) | (hash << 19); hash += (unsigned char)*name++; }
    return hash;
}
NOINLINE u32 djb2(const char *name) {
    u32 hash = 5381;
    while (*name) hash = hash * 33 + (unsigned char)*name++;
    return hash;
}
NOINLINE u32 fnv1a(const char *name) {
    u32 hash = 2166136261u;
    while (*name) hash = (hash ^ (unsigned char)*name++) * 16777619u;
    return hash;
}
NOINLINE u32 seeded(const char *name, u32 hash) {
    while (*name) hash = (hash ^ (unsigned char)*name++) * 16777619u;
    return hash;
}
NOINLINE u32 wide(const unsigned short *name) {
    u32 hash = 2166136261u;
    while (*name) hash = (hash ^ *name++) * 16777619u;
    return hash;
}
NOINLINE u32 crc32(const char *name) {
    u32 hash = ~0u;
    while (*name) {
        hash ^= (unsigned char)*name++;
        for (unsigned bit = 0; bit < 8; ++bit)
            hash = (hash >> 1) ^ (0xedb88320u & (0u - (hash & 1)));
    }
    return ~hash;
}
NOINLINE u32 custom(const char *name) {
    u32 hash = 1234567;
    while (*name) hash = (hash * 31) ^ ((unsigned char)*name++ + 17u);
    return hash;
}
NOINLINE u32 collision(const char *name) { (void)*(volatile const unsigned char *)name; return 42; }
NOINLINE u32 long_hash(const char *name) {
    u32 hash = (unsigned char)*name;
    for (volatile unsigned index = 0; index < 1000000; ++index) hash = hash * 33 + index;
    return hash;
}

#define RESOLVER(algorithm) \
NOINLINE Function resolve_##algorithm(u32 wanted) { \
    for (struct Module *module = modules; module; module = module->next) \
        for (usize index = 0; index < module->count; ++index) \
            if (algorithm(module->exports[index].name) == wanted) \
                return module->exports[index].address; \
    return (Function)0; \
}
RESOLVER(ror13)
RESOLVER(djb2)
RESOLVER(fnv1a)
NOINLINE Function resolve_seeded(u32 wanted) {
    for (struct Module *module = modules; module; module = module->next)
        for (usize index = 0; index < module->count; ++index)
            if (seeded(module->exports[index].name, 7) == wanted)
                return module->exports[index].address;
    return (Function)0;
}
NOINLINE Function resolve_wide(u32 wanted) {
    for (struct Module *module = modules; module; module = module->next)
        for (usize index = 0; index < module->count; ++index)
            if (wide((const unsigned short *)module->exports[index].name) == wanted)
                return module->exports[index].address;
    return (Function)0;
}
RESOLVER(crc32)
RESOLVER(custom)
RESOLVER(collision)
RESOLVER(long_hash)

#if defined(__i386__)
#define CASE(algorithm, constant) \
NOINLINE Function case_##algorithm(void) { return resolve_##algorithm(constant); }
#else
#define CASE(algorithm, constant) \
NOINLINE int case_##algorithm(int value) { \
    Function function = resolve_##algorithm(constant); \
    return function ? function(value) : -1; \
}
#endif
/* Constants for the export name "puts". */
CASE(ror13, 0xe3a01db3u)
CASE(djb2, 0x7c9c7b11u)
CASE(fnv1a, 0x9c67d227u)
CASE(seeded, 0x89112f9du)
CASE(wide, 0x9c67d227u)
CASE(crc32, 0x9a1e494fu)
CASE(custom, 0x7661fdcdu)
CASE(collision, 42)
CASE(long_hash, 42)
#if defined(__i386__)
NOINLINE Function case_unknown(void) { return resolve_fnv1a(1); }
#else
NOINLINE int case_unknown(int value) {
    Function function = resolve_fnv1a(1);
    return function ? function(value) : -1;
}
#endif

struct LoadedModule { struct LoadedModule *next; const unsigned char *image; };
struct LoadedModule *loaded_modules;
static u32 read32(const unsigned char *pointer) {
    return (u32)pointer[0] | ((u32)pointer[1] << 8) |
           ((u32)pointer[2] << 16) | ((u32)pointer[3] << 24);
}
static unsigned read16(const unsigned char *pointer) {
    return (unsigned)pointer[0] | ((unsigned)pointer[1] << 8);
}
NOINLINE Function resolve_pe(u32 wanted) {
    for (struct LoadedModule *module = loaded_modules; module; module = module->next) {
        const unsigned char *base = module->image;
        const unsigned char *nt = base + read32(base + 0x3c);
        unsigned directory = read16(nt + 0x18) == 0x20b ? 0x88 : 0x78;
        u32 export_rva = read32(nt + directory);
        if (!export_rva) continue;
        const unsigned char *exports = base + export_rva;
        u32 count = read32(exports + 0x18);
        const unsigned char *functions = base + read32(exports + 0x1c);
        const unsigned char *names = base + read32(exports + 0x20);
        const unsigned char *ordinals = base + read32(exports + 0x24);
        for (u32 index = 0; index < count; ++index) {
            const char *name = (const char *)(base + read32(names + index * 4));
            if (fnv1a(name) == wanted) {
                unsigned ordinal = read16(ordinals + index * 2);
                return (Function)(base + read32(functions + ordinal * 4));
            }
        }
    }
    return (Function)0;
}
CASE(pe, 0x9c67d227u)

struct Dynamic { usize tag, value; };
struct LinkMap { usize address; const char *name; const struct Dynamic *dynamic; struct LinkMap *next, *previous; };
struct Symbol {
    u32 name;
#if __SIZEOF_POINTER__ == 8
    unsigned char info, other; unsigned short section; usize value, size;
#else
    usize value, size; unsigned char info, other; unsigned short section;
#endif
};
struct LinkMap *link_map;
NOINLINE Function resolve_elf(u32 wanted) {
    for (struct LinkMap *module = link_map; module; module = module->next) {
        const char *strings = (const char *)0;
        const struct Symbol *symbols = (const struct Symbol *)0;
        const u32 *table = (const u32 *)0;
        for (const struct Dynamic *dynamic = module->dynamic; dynamic->tag; ++dynamic) {
            if (dynamic->tag == 5) strings = (const char *)(module->address + dynamic->value);
            if (dynamic->tag == 6) symbols = (const struct Symbol *)(module->address + dynamic->value);
            if (dynamic->tag == 4) table = (const u32 *)(module->address + dynamic->value);
        }
        if (!strings || !symbols || !table) continue;
        for (u32 index = 1; index < table[1]; ++index) {
            if (djb2(strings + symbols[index].name) == wanted)
                return (Function)(module->address + symbols[index].value);
        }
    }
    return (Function)0;
}
CASE(elf, 0x7c9c7b11u)

#ifdef NATIVE
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc != 3) return 1;
    u32 (*routines[])(const char *) = { ror13, djb2, fnv1a, crc32, custom };
    unsigned index = (unsigned)atoi(argv[1]);
    if (index >= sizeof(routines) / sizeof(routines[0])) return 1;
    printf("%u\n", routines[index](argv[2]));
    return 0;
}
#endif
