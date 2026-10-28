.text
.globl main
.type main,%function
main:
#if defined(__x86_64__)
    lea buffer(%rip), %rdi
    lea message(%rip), %rsi
    mov $4, %ecx
    rep movsb
    mov $7, %r10d
    sub $8, %rsp
    call custom
    add $8, %rsp
    mov $1, %eax
    mov $1, %edi
    lea buffer(%rip), %rsi
    mov $4, %edx
    syscall
    xor %eax, %eax
    ret
#elif defined(__i386__)
    push %ebx
    push %edi
    push %esi
    mov $buffer, %edi
    mov $message, %esi
    mov $4, %ecx
    rep movsb
    mov $7, %edx
    call custom
    mov $4, %eax
    mov $1, %ebx
    mov $buffer, %ecx
    mov $4, %edx
    int $0x80
    pop %esi
    pop %edi
    pop %ebx
    xor %eax, %eax
    ret
#elif defined(__aarch64__)
    stp x29, x30, [sp, #-16]!
    mov x9, #7
    bl custom
    mov x0, #1
    adr x1, message
    mov x2, #4
    mov x8, #64
    svc #0
    ldp x29, x30, [sp], #16
    mov x0, #0
    ret
#elif defined(__arm__)
    push {r4, r5, r7, lr}
    mov r4, #7
    bl custom
    mov r0, #1
    adr r1, message
    mov r2, #4
    mov r7, #4
    svc #0
    pop {r4, r5, r7, lr}
    mov r0, #0
    bx lr
#endif
.size main,.-main
.type custom,%function
custom:
#if defined(__x86_64__)
    lea 1(%r10), %eax
    ret
#elif defined(__i386__)
    lea 1(%edx), %eax
    ret
#elif defined(__aarch64__)
    add x0, x9, #1
    ret
#elif defined(__arm__)
    add r0, r4, #1
    bx lr
#endif
.size custom,.-custom
message: .ascii "test"
.data
buffer: .space 4
