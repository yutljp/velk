.text
.globl _start
.type _start,@function
_start:
    movl $125, %eax
    movl $target, %ebx
    andl $-4096, %ebx
    movl $4096, %ecx
    movl $7, %edx
    int $0x80
    movl $target, %esi
    movl $12, %ecx
1:
    xorb $0xaa, (%esi)
    incl %esi
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
