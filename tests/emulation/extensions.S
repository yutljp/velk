.syntax unified
.text
#if defined(__thumb__)
.thumb
#else
.arm
#endif
.macro function name, instruction, rotation
.global \name
.type \name, %function
#if defined(__thumb__)
.thumb_func
#endif
\name:
\instruction r0, r0, r1, ror #\rotation
bx lr
.size \name, .-\name
.endm
function extend_byte, uxtab, 0
function extend_half, uxtah, 8
function extend_signed_byte, sxtab, 16
function extend_signed_half, sxtah, 24
