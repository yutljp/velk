.text
.globl _start
.type _start,@function
_start:
    movl $10, %eax
    leaq target(%rip), %rdi
    andq $-4096, %rdi
    movl $4096, %esi
    movl $7, %edx
    syscall
    leaq target(%rip), %rsi
    movl $12, %ecx
1:
    xorb $0xaa, (%rsi)
    incq %rsi
    decl %ecx
    jnz 1b
    jmp target
.size _start, .-_start

.balign 16
.globl target
.type target,@function
target:
    .byte 0x3a, 0x3a, 0x3a, 0x3a, 0x3a, 0x3a
    .byte 0x12, 0x80, 0xaa, 0xaa, 0xaa, 0x69
.size target, .-target
