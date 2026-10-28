.text
.macro select name, condition, width=32
.global select_\name
.type select_\name,%function
select_\name:
    mov w4, #2
    cbz w2, 1f
 .if \width == 64
    adds x3, x0, x1
.else
    adds w3, w0, w1
.endif
    b 2f
1:
.if \width == 64
    subs x3, x0, x1
.else
    subs w3, w0, w1
.endif
2:  mov w5, #0
    b 3f
3:  cset w0, \condition
    sub w4, w4, #1
    cbnz w4, 3b
    ret
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

select eq_64, eq, 64
select ne_64, ne, 64
select cs_64, cs, 64
select cc_64, cc, 64
select mi_64, mi, 64
select pl_64, pl, 64
select vs_64, vs, 64
select vc_64, vc, 64
select hi_64, hi, 64
select ls_64, ls, 64
select ge_64, ge, 64
select lt_64, lt, 64
select gt_64, gt, 64
select le_64, le, 64
