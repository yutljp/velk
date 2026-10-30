typedef __UINTPTR_TYPE__ word;
#define API __declspec(dllimport)
#define EXPORT __declspec(dllexport)
API int printf(const char *, ...);
API void __stdcall ExitProcess(unsigned);
API void __stdcall SetLastError(unsigned);
struct exception_record {
    unsigned code, flags;
    struct exception_record *previous;
    void *address;
    unsigned count;
    word information[15];
};
EXPORT unsigned fault(unsigned);
extern void after_fault(void);
extern void context_return(void);
EXPORT unsigned observed[4];
EXPORT unsigned action;
EXPORT unsigned searched;
static word last_context;
EXPORT word observed_address(void) { return (word)observed; }
EXPORT word action_address(void) { return (word)&action; }
EXPORT word searched_address(void) { return (word)&searched; }
EXPORT word context_pointer_address(void) { return (word)&last_context; }
EXPORT unsigned decline_handler(struct exception_record *record, word frame, unsigned char *context, void *dispatcher) {
    (void)record; (void)frame; (void)context; (void)dispatcher;
    searched++;
    return 1;
}
EXPORT unsigned exception_handler(struct exception_record *record, word frame, unsigned char *context, void *dispatcher) {
    (void)frame; (void)dispatcher;
    last_context = (word)context;
    observed[0] = record->code;
    observed[1]++;
    observed[2] = record->code == 0xc0000005 && record->count == 2 ? (unsigned)record->information[0] + 1 : 0;
    observed[3] = record->code == 0xc0000005 ? (unsigned)record->information[1] : 0;
    if (action == 1 || action == 2) return action;
    if (action == 3) observed[3] = *(volatile unsigned *)(context + (sizeof(word) == 8 ? 68 : 192));
    if (action == 4) *(unsigned *)(context + (sizeof(word) == 8 ? 68 : 192)) = 0x202;
    if (action == 5) *(volatile unsigned *)0 = 7;
    if (action == 6) { *(word *)(context + (sizeof(word) == 8 ? 248 : 184)) = 0; return 0; }
    if (action == 7) { if (sizeof(word) == 4) *(word *)frame = frame; return 1; }
    if (action == 8) ExitProcess(37);
    if (action == 9) return 0;
    if (action == 10) {
        *(unsigned short *)(context + (sizeof(word) == 8 ? 184 : 168)) = 0x123;
        *(word *)(context + (sizeof(word) == 8 ? 248 : 184)) = (word)context_return;
        return 0;
    }
    *(word *)(context + (sizeof(word) == 8 ? 248 : 184)) = (word)after_fault;
    *(word *)(context + (sizeof(word) == 8 ? 120 : 176)) = 37;
    return 0;
}
EXPORT unsigned run_exception(unsigned mode) { return fault(mode); }
#ifdef __x86_64__
EXPORT unsigned fault_epilogue(unsigned);
EXPORT unsigned run_epilogue(unsigned mode) { return fault_epilogue(mode); }
EXPORT unsigned fault_prefixed_return(unsigned);
EXPORT unsigned run_prefixed_return(unsigned mode) { return fault_prefixed_return(mode); }
#endif
EXPORT unsigned run_undefined_context(void) { SetLastError(0); return fault(0); }
EXPORT void entry(void) {
    for (unsigned mode = 0; mode < 4; mode++) {
        unsigned value = run_exception(mode);
        printf("%u %u %x %u %u %u\n", mode, value, observed[0], observed[1], observed[2], observed[3]);
    }
#ifdef __x86_64__
    printf("prefixed:%u\n", run_prefixed_return(0));
#endif
    ExitProcess(37);
}
