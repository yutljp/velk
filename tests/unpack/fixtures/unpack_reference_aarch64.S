.text
.globl target
.type target,%function
target:
    nop
    nop
    mov x0, #42
    ret
.size target, .-target
