.syntax unified
.text
.arm
.global pc_load_arm
.type pc_load_arm,%function
pc_load_arm:
    ldr pc, [r1, #4]!
.global pc_load_arm_target
pc_load_arm_target:
    mov r0, r1
    bx lr
.size pc_load_arm, .-pc_load_arm
.thumb
.thumb_func
.global pc_load_thumb
.type pc_load_thumb,%function
pc_load_thumb:
    ldr pc, [r1, #4]!
.global pc_load_thumb_target
.thumb_func
pc_load_thumb_target:
    mov r0, r1
    bx lr
.size pc_load_thumb, .-pc_load_thumb
.arm
.macro select name, condition
.global select_\name
.type select_\name,%function
select_\name:
    cmp r2, #0
    beq 1f
    adds r3, r0, r1
    b 2f
1:  subs r3, r0, r1
2:  mov r4, #0
    b 3f
3:  mov r3, #0
    mov\condition r3, #1
    mov r0, r3
    bx lr
.size select_\name, .-select_\name
.endm
select eq, eq
select ne, ne
select cs, cs
select cc, cc
select mi, mi
select pl, pl
select vs, vs
select vc, vc
select hi, hi
select ls, ls
select ge, ge
select lt, lt
select gt, gt
select le, le
.global pc_load_ip
.type pc_load_ip,%function
pc_load_ip:
    mov r12, r1
    ldr pc, [r12, #4]!
    mov r0, r12
    bx lr
.size pc_load_ip, .-pc_load_ip

// The destination consumes the written-back ip, within the same function.
.macro internal_pc name, thumb_source, thumb_target, offset, register=0, delta=0, prefix=0
.balign 4
.if \thumb_source
.thumb
.thumb_func
.else
.arm
.endif
.global pc_internal_\name
.type pc_internal_\name,%function
pc_internal_\name:
.if \offset < 0
    adr ip, 1f + 4
.else
    adr ip, 1f
.endif
.if \register
    mov r2, #4
.if \register == 2
    ldr pc, [ip, r2, lsl #1]!
.else
    ldr pc, [ip, r2]!
.endif
.else
    ldr pc, [ip, #\offset]!
.endif
.balign 4
1:
.if \offset >= 0
    .word 0
.endif
.if \register == 2
    .word 0
.endif
    .word 3f + \delta
.if \thumb_target
.thumb
.thumb_func
.else
.balign 4
.arm
.endif
2:
.if \prefix
    mov r0, #99
.endif
.if \thumb_target
.thumb_func
.endif
3:
    mov r0, ip
    bx lr
.size pc_internal_\name, .-pc_internal_\name
.endm
internal_pc arm, 0, 0, 4
internal_pc thumb, 1, 1, 4
internal_pc arm_thumb, 0, 1, 4
internal_pc thumb_arm, 1, 0, 4
internal_pc register, 0, 0, 4, 1
internal_pc shifted, 0, 0, 8, 2
internal_pc negative, 0, 0, -4
internal_pc split, 0, 0, 4, 0, 0, 1
internal_pc invalid_mode, 0, 1, 4, 0, -1
internal_pc unaligned, 0, 0, 4, 0, 2
internal_pc outside, 0, 0, 4, 0, 0x10000000
