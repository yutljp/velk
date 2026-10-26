.text
.p2align 2
.globl _signed_return
_signed_return:
    pacibsp
    add x0, x0, #7
    retab
.globl _signed_return_a
_signed_return_a:
    paciasp
    add x0, x0, #9
    retaa
.globl _authenticated_return
_authenticated_return:
    pacibsp
    autibsp
    ret
.globl _authenticated_return_a
_authenticated_return_a:
    paciasp
    autiasp
    ret
.globl _pointer_identity
_pointer_identity:
    pacia x0, x1
    autia x0, x1
    pacib x0, x1
    autib x0, x1
    pacda x0, x1
    autda x0, x1
    pacdb x0, x1
    autdb x0, x1
    paciza x0
    autiza x0
    pacizb x0
    autizb x0
    pacdza x0
    autdza x0
    pacdzb x0
    autdzb x0
    xpaci x0
    xpacd x0
    ret
.globl _load_a
_load_a:
    ldraa x0, [x0, #8]
    ret
.globl _load_b
_load_b:
    ldrab x0, [x0, #-8]
    ret
.globl _load_writeback
_load_writeback:
    ldraa x2, [x0, #8]!
    add x0, x0, x2
    ret
.globl _load_sp
_load_sp:
    sub sp, sp, #16
    str x0, [sp]
    ldraa x0, [sp]
    add sp, sp, #16
    ret
.macro branch name, instruction
.globl _\name
_\name:
    \instruction x0, x1
.endmacro
branch branch_a, braa
branch branch_b, brab
.macro branch_zero name, instruction
.globl _\name
_\name:
    \instruction x0
.endmacro
branch_zero branch_az, braaz
branch_zero branch_bz, brabz
.macro invoke name, instruction
.globl _\name
_\name:
    stp xzr, x30, [sp, #-16]!
    \instruction x0, x1
    ldp xzr, x30, [sp], #16
    ret
.endmacro
invoke invoke_a, blraa
invoke invoke_b, blrab
.macro invoke_zero name, instruction
.globl _\name
_\name:
    stp xzr, x30, [sp, #-16]!
    \instruction x0
    ldp xzr, x30, [sp], #16
    ret
.endmacro
invoke_zero invoke_az, blraaz
invoke_zero invoke_bz, blrabz
.globl _pointer_hints
_pointer_hints:
    pacia1716
    autia1716
    pacib1716
    autib1716
    paciaz
    autiaz
    pacibz
    autibz
    xpaclri
    ret
