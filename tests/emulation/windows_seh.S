#ifdef __x86_64__
#define NAME(x) x
    .text
    .globl fault
    .seh_proc fault
fault:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_handler exception_handler, @except
    .seh_endprologue
    call fault_middle
    nop
    addq $40, %rsp
    ret
    .seh_endproc
    .globl fault_epilogue
    .seh_proc fault_epilogue
fault_epilogue:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_handler exception_handler, @except
    .seh_endprologue
    call fault_middle
    addq $40, %rsp
    ret
    .seh_endproc
    .globl fault_prefixed_return
    .seh_proc fault_prefixed_return
fault_prefixed_return:
    subq $40, %rsp
    .seh_stackalloc 40
    .seh_handler exception_handler, @except
    .seh_endprologue
    call fault_middle
    .byte 0x67
    addq $40, %rsp
    ret
    .seh_endproc
    .seh_proc fault_middle
fault_middle:
    pushq %rbp
    .seh_pushreg %rbp
    pushq %rbx
    .seh_pushreg %rbx
    subq $136, %rsp
    .seh_stackalloc 136
    movq %r12, 48(%rsp)
    .seh_savereg %r12, 48
    leaq 128(%rsp), %rbp
    .seh_setframe %rbp, 128
    .seh_endprologue
    movq $123, %r12
    call fault_leaf
    movq 48(%rsp), %r12
    addq $136, %rsp
    popq %rbx
    popq %rbp
    ret
    .seh_endproc
    .globl fault_leaf
    .seh_proc fault_leaf
fault_leaf:
    .seh_handler decline_handler, @except
    .seh_endprologue
    cmpl $1, %ecx
    je divide
    cmpl $2, %ecx
    je breakpoint
    cmpl $3, %ecx
    je write_fault
    xorq %rax, %rax
    movl (%rax), %eax
    jmp after_fault
write_fault:
    xorq %rax, %rax
    movl $7, (%rax)
    jmp after_fault
divide:
    xorl %edx, %edx
    movl $37, %eax
    xorl %ecx, %ecx
    divl %ecx
    jmp after_fault
breakpoint:
    int3
    .globl after_fault
after_fault:
    ret
    .seh_endproc
    .globl context_return
context_return:
    movq %r8, %rax
    ret
#else
    .text
    .globl _fault
_fault:
    pushl %ebp
    movl %esp, %ebp
    pushl $_exception_handler
    pushl %fs:0
    movl %esp, %fs:0
    pushl $_decline_handler
    pushl %fs:0
    movl %esp, %fs:0
    movl 8(%ebp), %ecx
    call _fault_leaf
    popl %fs:0
    addl $4, %esp
    popl %fs:0
    addl $4, %esp
    popl %ebp
    ret
    .globl _fault_leaf
_fault_leaf:
    cmpl $1, %ecx
    je divide
    cmpl $2, %ecx
    je breakpoint
    cmpl $3, %ecx
    je write_fault
    xorl %eax, %eax
    movl (%eax), %eax
    jmp _after_fault
write_fault:
    xorl %eax, %eax
    movl $7, (%eax)
    jmp _after_fault
divide:
    xorl %edx, %edx
    movl $37, %eax
    xorl %ecx, %ecx
    divl %ecx
    jmp _after_fault
breakpoint:
    int3
    .globl _after_fault
_after_fault:
    ret
    .globl _context_return
_context_return:
    movl %edx, %eax
    ret
#endif
