.text
.globl _start
.type _start,%function
_start:
    adrp x0, target
    mov x1, #4096
    mov x2, #7
    mov x8, #226
    svc #0
    adr x0, target
    mov x1, #16
    mov w3, #0xaa
1:
    ldrb w2, [x0]
    eor w2, w2, w3
    strb w2, [x0], #1
    subs x1, x1, #1
    b.ne 1b
    b target
.size _start, .-_start

.balign 16
.globl target
.type target,%function
target:
    .byte 0xb5, 0x8a, 0xa9, 0x7f, 0xb5, 0x8a, 0xa9, 0x7f
    .byte 0xea, 0xaf, 0x2a, 0x78, 0x6a, 0xa9, 0xf5, 0x7c
.size target, .-target
