.text
.global io_entry, unknown, terminate, terminate_group
.type io_entry,%function
.type unknown,%function
.type terminate,%function
.type terminate_group,%function
#if defined(__x86_64__)
io_entry:
    xor %eax, %eax
    xor %edi, %edi
    lea buffer(%rip), %rsi
    mov $4, %edx
    syscall
    mov %eax, %edx
    mov $1, %eax
    mov $1, %edi
    syscall
    ret
unknown:
    mov $9999, %eax
    syscall
    ret
terminate:
    mov $60, %eax
    xor %edi, %edi
    syscall
    ud2
terminate_group:
    mov $231, %eax
    xor %edi, %edi
    syscall
    ud2
#elif defined(__i386__)
io_entry:
    mov $3, %eax
    xor %ebx, %ebx
    mov $buffer, %ecx
    mov $4, %edx
    int $0x80
    mov %eax, %edx
    mov $4, %eax
    mov $1, %ebx
    int $0x80
    ret
unknown:
    mov $9999, %eax
    int $0x80
    ret
terminate:
    mov $1, %eax
    xor %ebx, %ebx
    int $0x80
    ud2
terminate_group:
    mov $252, %eax
    xor %ebx, %ebx
    int $0x80
    ud2
#else
io_entry:
    mov x8, #63
    mov x0, #0
    adrp x1, buffer
    add x1, x1, :lo12:buffer
    mov x2, #4
    svc #0
    mov x2, x0
    mov x0, #1
    mov x8, #64
    svc #0
    ret
unknown:
    mov x8, #9999
    svc #0
    ret
terminate:
    mov x8, #93
    mov x0, #0
    svc #0
    brk #0
terminate_group:
    mov x8, #94
    mov x0, #0
    svc #0
    brk #0
#endif
#if defined(__i386__)
.global nested
.type nested,%function
nested:
    call io_entry
    ret
#endif
.bss
buffer: .skip 128
.section .note.GNU-stack,"",%progbits
