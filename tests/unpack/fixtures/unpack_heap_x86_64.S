.text
.globl _start
.type _start,@function
_start:
    leaq payload(%rip), %rsi
    movl $0x10000000, %edi
    movl $12, %ecx
1:
    movb (%rsi), %al
    movb %al, (%rdi)
    incq %rsi
    incq %rdi
    decl %ecx
    jnz 1b
    movl $0x10000000, %eax
    jmp *%rax
.size _start, .-_start

.balign 16
payload:
    .byte 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
    .byte 0xb8, 42, 0, 0, 0, 0xc3
