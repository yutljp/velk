.text
.global local_length
.type local_length,%function
local_length:
.rept 32
nop
.endr
#if defined(__x86_64__)
xor %eax,%eax
cmpb $0,(%rdi)
je 2f
cmpb $0,1(%rdi)
jne 1f
mov $1,%eax
ret
1:
cmpb $0,(%rdi,%rax)
je 2f
inc %rax
jmp 1b
2:
ret
#else
mov x0,x0
mov x1,x0
mov x0,#0
1:
ldrb w2,[x1,x0]
cbz w2,2f
add x0,x0,#1
b 1b
2:
ret
#endif
.size local_length,.-local_length

.global tail_length
.type tail_length,%function
tail_length:
#if defined(__x86_64__)
jmp local_length
#else
b local_length
#endif
.size tail_length,.-tail_length

.global tail_import
.type tail_import,%function
tail_import:
#if defined(__x86_64__)
jmp strlen
#else
b strlen
#endif
.size tail_import,.-tail_import

.global nested_tail
.type nested_tail,%function
nested_tail:
#if defined(__x86_64__)
sub $8,%rsp
call tail_length
add $8,%rsp
add $7,%rax
ret
#else
stp x29,x30,[sp,#-16]!
bl tail_length
ldp x29,x30,[sp],#16
add x0,x0,#7
ret
#endif
.size nested_tail,.-nested_tail
.section .note.GNU-stack,"",%progbits
.text
.global tail_scan
.type tail_scan,%function
tail_scan:
#if defined(__x86_64__)
jmp sscanf
#else
b sscanf
#endif
.size tail_scan,.-tail_scan
.section .rodata
.global scan_format
.type scan_format,%object
scan_format:
.asciz "%c%c%c%c%c%c%c"
.size scan_format,.-scan_format
