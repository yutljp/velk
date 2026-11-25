// A start that copies the code restoring the packed part into memory it
// allocates and runs it from there before it runs the packed part.
.text
.globl entry
entry:
    subq $40, %rsp
    xorl %ecx, %ecx
    movl $4096, %edx
    movl $0x3000, %r8d
    movl $0x40, %r9d
    callq *__imp_VirtualAlloc(%rip)
    movq %rax, %r10
    leaq stage(%rip), %rsi
    movq %rax, %rdi
    movl $(stage_end - stage), %ecx
    rep movsb
    leaq payload_start(%rip), %rcx
    leaq payload_end(%rip), %rdx
    callq *%r10
    addq $40, %rsp
    jmp original
stage:
    xorb $0x5a, (%rcx)
    incq %rcx
    cmpq %rdx, %rcx
    jne stage
    ret
stage_end:
