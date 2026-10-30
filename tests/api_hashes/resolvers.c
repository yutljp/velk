typedef unsigned int u32;
typedef __SIZE_TYPE__ usize;
typedef u32 (*Function)(void);

#define NOINLINE __attribute__((noinline))
#if defined(__i386__) && defined(__OPTIMIZE__)
#define DYNAMIC_RESOLVER_ATTRIBUTES __attribute__((noinline, optnone))
#else
#define DYNAMIC_RESOLVER_ATTRIBUTES NOINLINE
#endif

NOINLINE u32 puts(void) { return 7; }

struct Export {
    const char *name;
    Function address;
};

struct Module {
    struct Module *next;
    const struct Export *exports;
    usize count;
};

static const struct Export inline_exports[] = {{"puts", puts}};
static const struct Module inline_module = {0, inline_exports, 1};
static struct Module *volatile inline_modules = (struct Module *)&inline_module;

NOINLINE Function resolve_inline(u32 wanted) {
    for (struct Module *module = inline_modules; module; module = module->next) {
        for (usize index = 0; index < module->count; ++index) {
            const unsigned char *name =
                (const unsigned char *)module->exports[index].name;
            u32 hash = 2166136261u;
            while (*name) hash = (hash ^ *name++) * 16777619u;
            if (hash == wanted) return module->exports[index].address;
        }
    }
    return (Function)0;
}

NOINLINE u32 case_inline(void) {
    Function function = resolve_inline(0x9c67d227u);
    return function ? function() : 0;
}

struct Dynamic {
    usize tag;
    usize value;
};

struct LinkMap {
    usize address;
    const char *name;
    const struct Dynamic *dynamic;
    struct LinkMap *next;
    struct LinkMap *previous;
};

struct Symbol {
    u32 name;
#if __SIZEOF_POINTER__ == 8
    unsigned char info;
    unsigned char other;
    unsigned short section;
    usize value;
    usize size;
#else
    usize value;
    usize size;
    unsigned char info;
    unsigned char other;
    unsigned short section;
#endif
};

static const char symbol_names[] = "\0puts";
static const struct Symbol symbols[] = {
    {.name = 0},
    {.name = 1, .value = (usize)puts},
};
static const u32 hash_table[] = {1, 2, 1, 0, 0};
static const struct Dynamic dynamic_entries[] = {
    {4, (usize)hash_table},
    {5, (usize)symbol_names},
    {6, (usize)symbols},
    {0, 0},
};
static struct LinkMap dynamic_module = {0, "fixture", dynamic_entries, 0, 0};
static struct LinkMap *volatile link_map = &dynamic_module;

DYNAMIC_RESOLVER_ATTRIBUTES Function resolve_dynamic(u32 wanted) {
    for (struct LinkMap *module = link_map; module; module = module->next) {
        const char *strings = (const char *)0;
        const struct Symbol *symbol_table = (const struct Symbol *)0;
        const u32 *table = (const u32 *)0;
        for (const struct Dynamic *dynamic = module->dynamic; dynamic->tag; ++dynamic) {
            if (dynamic->tag == 5) strings = (const char *)(module->address + dynamic->value);
            if (dynamic->tag == 6)
                symbol_table = (const struct Symbol *)(module->address + dynamic->value);
            if (dynamic->tag == 4) table = (const u32 *)(module->address + dynamic->value);
        }
        if (!strings || !symbol_table || !table) continue;
        for (u32 index = 1; index < table[1]; ++index) {
            const unsigned char *name =
                (const unsigned char *)(strings + symbol_table[index].name);
            u32 hash = 5381;
            while (*name) hash = hash * 33 + *name++;
            if (hash == wanted)
                return (Function)(module->address + symbol_table[index].value);
        }
    }
    return (Function)0;
}

NOINLINE u32 case_dynamic(void) {
    Function function = resolve_dynamic(0x7c9c7b11u);
    return function ? function() : 0;
}

NOINLINE u32 case_dynamic_unknown(void) {
    Function function = resolve_dynamic(1);
    return function ? function() : 0;
}

#ifdef NATIVE
int main(void) {
    if (case_inline() != 7 || case_dynamic() != 7 || case_dynamic_unknown() != 0) return 1;
    return 0;
}
#endif
