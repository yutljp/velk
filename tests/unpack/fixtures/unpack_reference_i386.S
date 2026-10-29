.text
.globl target
.type target,@function
target:
    .fill 6, 1, 0x90
    movl $42, %eax
    ret
.size target, .-target
