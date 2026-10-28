.text
.macro select name, condition, width=32
.global select_\name
.type select_\name,@function
select_\name:
    testl %edx, %edx
    jz 1f
    movl %edi, %eax
.if \width == 8
    movl %esi, %ecx
    addb %cl, %al
.elseif \width == 16
    addw %si, %ax
.elseif \width == 64
    movq %rdi, %rax
    addq %rsi, %rax
.else
    addl %esi, %eax
.endif
    jmp 2f
1:  movl %edi, %eax
.if \width == 8
    movl %esi, %ecx
    subb %cl, %al
.elseif \width == 16
    subw %si, %ax
.elseif \width == 64
    movq %rdi, %rax
    subq %rsi, %rax
.else
    subl %esi, %eax
.endif
2:  movl $0, %ecx
    jmp 3f
3:  set\condition %al
    movzbl %al, %eax
    ret
.size select_\name, .-select_\name
.endm
select eq, e
select ne, ne
select cs, ae
select cc, b
select mi, s
select pl, ns
select vs, o
select vc, no
select hi, a
select ls, be
select ge, ge
select lt, l
select gt, g
select le, le
select pe, p
select po, np

select eq_8, e, 8
select ne_8, ne, 8
select cs_8, ae, 8
select cc_8, b, 8
select mi_8, s, 8
select pl_8, ns, 8
select vs_8, o, 8
select vc_8, no, 8
select hi_8, a, 8
select ls_8, be, 8
select ge_8, ge, 8
select lt_8, l, 8
select gt_8, g, 8
select le_8, le, 8
select pe_8, p, 8
select po_8, np, 8
select eq_16, e, 16
select ne_16, ne, 16
select cs_16, ae, 16
select cc_16, b, 16
select mi_16, s, 16
select pl_16, ns, 16
select vs_16, o, 16
select vc_16, no, 16
select hi_16, a, 16
select ls_16, be, 16
select ge_16, ge, 16
select lt_16, l, 16
select gt_16, g, 16
select le_16, le, 16
select pe_16, p, 16
select po_16, np, 16

#ifndef __i386__
select eq_64, e, 64
select ne_64, ne, 64
select cs_64, ae, 64
select cc_64, b, 64
select mi_64, s, 64
select pl_64, ns, 64
select vs_64, o, 64
select vc_64, no, 64
select hi_64, a, 64
select ls_64, be, 64
select ge_64, ge, 64
select lt_64, l, 64
select gt_64, g, 64
select le_64, le, 64
select pe_64, p, 64
select po_64, np, 64
#endif
