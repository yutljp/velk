.section .text.tail,"ax",%progbits
.globl branch_tail
.type branch_tail,%function
branch_tail:
#if defined(__x86_64__) || defined(__i386__)
.byte 0xe8, 0, 0, 0, 0
#elif defined(__aarch64__)
.word 0x94000000
#elif defined(__arm__)
.word 0xeb000000
#endif
.size branch_tail, .-branch_tail
.section .note.GNU-stack,"",%progbits
