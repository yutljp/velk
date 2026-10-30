typedef unsigned int u32;
typedef unsigned short u16;
typedef __UINTPTR_TYPE__ usize;
typedef u32 (*Function)(void);

#define NOINLINE __attribute__((noinline))

static u32 read32(const unsigned char *address) {
    return (u32)address[0] | ((u32)address[1] << 8) |
           ((u32)address[2] << 16) | ((u32)address[3] << 24);
}

static u16 read16(const unsigned char *address) {
    return (u16)((u16)address[0] | ((u16)address[1] << 8));
}

NOINLINE Function resolve_pe(u32 wanted) {
    usize peb;
#if __SIZEOF_POINTER__ == 8
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
    const usize ldr_offset = 0x18;
    const usize list_offset = 0x20;
    const usize link_offset = 0x10;
    const usize image_offset = 0x30;
    const usize name_offset = 0x58;
#else
    __asm__ volatile("movl %%fs:0x30, %0" : "=r"(peb));
    const usize ldr_offset = 0x0c;
    const usize list_offset = 0x14;
    const usize link_offset = 0x08;
    const usize image_offset = 0x18;
    const usize name_offset = 0x2c;
#endif
    const usize ldr = *(const usize *)(peb + ldr_offset);
    const usize head = ldr + list_offset;
    usize link = *(const usize *)head;
    while (link != head) {
        const usize entry = link - link_offset;
        const usize base = *(const usize *)(entry + image_offset);
        const u16 name_bytes = *(const u16 *)(entry + name_offset);
        const u16 *module_name = *(const u16 **)(entry + name_offset + sizeof(usize));
        u32 module_hash = 2166136261u;
        for (u32 index = 0; index < name_bytes / 2; ++index) {
            u16 unit = module_name[index];
            if (unit >= 'A' && unit <= 'Z') unit += 'a' - 'A';
            module_hash = (module_hash ^ unit) * 16777619u;
        }

        const unsigned char *nt = (const unsigned char *)base +
                                  read32((const unsigned char *)base + 0x3c);
        const u32 directory = read16(nt + 0x18) == 0x20b ? 0x88 : 0x78;
        const u32 export_rva = read32(nt + directory);
        if (export_rva) {
            const unsigned char *exports = (const unsigned char *)base + export_rva;
            const u32 count = read32(exports + 0x18);
            const u32 *functions = (const u32 *)(base + read32(exports + 0x1c));
            const u32 *names = (const u32 *)(base + read32(exports + 0x20));
            const u16 *ordinals = (const u16 *)(base + read32(exports + 0x24));
            for (u32 index = 0; index < count; ++index) {
                const unsigned char *name = (const unsigned char *)(base + names[index]);
                u32 hash = module_hash;
                while (*name) hash = (hash ^ *name++) * 16777619u;
                if (hash == wanted)
                    return (Function)(base + functions[ordinals[index]]);
            }
        }
        link = *(const usize *)link;
    }
    return (Function)0;
}

NOINLINE u32 case_pe(void) {
    Function function = resolve_pe(0x8aa51aa2u);
    return function ? function() : 0;
}
