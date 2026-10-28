.text
.globl enclosing
.type enclosing,@function
enclosing:
#ifdef SHARED_FALLTHROUGH
    nop
#else
    jmp continuation
#endif
.globl called
called:
#ifdef __x86_64__
    lea 7(%rdi), %eax
#else
    mov 4(%esp), %eax
    add $7, %eax
#endif
    ret
.globl uncalled
uncalled:
    mov $99, %eax
    ret
continuation:
#ifdef __x86_64__
    lea 11(%rdi), %eax
#else
    mov 4(%esp), %eax
    add $11, %eax
#endif
    ret
#ifndef ESTIMATED
.size enclosing, .-enclosing
#endif

.globl caller
.type caller,@function
caller:
#ifdef ENTRY_ONLY
    mov $3, %eax
#else
#ifdef __x86_64__
    sub $8, %rsp
    call called
    add $8, %rsp
#else
    push 4(%esp)
    call called
    add $4, %esp
#endif
#endif
    ret
.size caller, .-caller

#ifdef STARTUP
.globl startup
.type startup,@function
startup:
#ifdef ABSOLUTE_STARTUP
    mov $called, %rdi
#else
    lea called(%rip), %rdi
#endif
#ifdef CLOBBER_ARGUMENT
    mov %rsi, %rdi
#endif
#ifdef DIRECT_STARTUP
    call __libc_start_main@PLT
#else
    call *__libc_start_main@GOTPCREL(%rip)
#endif
    hlt
.size startup, .-startup
#endif
.section .note.GNU-stack,"",@progbits
