// A start that copies the code restoring the packed part into memory it
// allocates and runs it from there before it runs the packed part. The
// 64-bit one jumps to the copy, which jumps on to the packed part; the
// 32-bit one calls the copy and continues when it returns.
.text
#ifdef __x86_64__
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
    leaq original(%rip), %r8
    addq $40, %rsp
    jmpq *%r10
stage:
    xorb $0x5a, (%rcx)
    incq %rcx
    cmpq %rdx, %rcx
    jne stage
    jmpq *%r8
stage_end:
#else
.globl _entry
_entry:
    pushl $0x40
    pushl $0x3000
    pushl $4096
    pushl $0
    calll *__imp__VirtualAlloc@16
    movl %eax, %ebx
    movl $stage, %esi
    movl %eax, %edi
    movl $(stage_end - stage), %ecx
    rep movsb
    movl $_payload_start, %ecx
    movl $_payload_end, %edx
    calll *%ebx
    jmp _original
stage:
    xorb $0x5a, (%ecx)
    incl %ecx
    cmpl %edx, %ecx
    jne stage
    ret
stage_end:
#endif
