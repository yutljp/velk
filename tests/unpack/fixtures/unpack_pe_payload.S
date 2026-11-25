// The packed part: a function that calls one of its imports, and the
// slots the imports are resolved into, a zero after each library.
#ifdef __x86_64__
#define NAME(name) name
#define WORD 8
#else
#define NAME(name) _##name
#define WORD 4
#endif
.section .payload,"xw"
.globl NAME(payload_start)
.globl NAME(payload_end)
.globl NAME(payload_imports)
.globl NAME(original)
NAME(payload_start):
NAME(original):
#ifdef __x86_64__
    subq $40, %rsp
    callq *NAME(payload_imports)+3*WORD(%rip)
    addq $40, %rsp
#else
    calll *NAME(payload_imports)+3*WORD
#endif
    addl $42, %eax
    ret
.balign 8
NAME(payload_imports):
    .fill 5, WORD, 0
NAME(payload_end):
