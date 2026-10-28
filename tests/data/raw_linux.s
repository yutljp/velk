.intel_syntax noprefix
.text
.globl _start, main, frame_dummy, success, failure, puts
.type _start,@function
_start:
    call main
    mov edi, eax
    mov eax, 60
    syscall
.size _start, .-_start
.type main,@function
main:
    push rbx
    lea rdi, [rip + input]
    xor eax, eax
    mov ecx, 128
    cld
    rep stosb
    xor eax, eax
    xor edi, edi
    lea rsi, [rip + input]
    mov edx, 128
    syscall
    call .Lframed
    sub rax, 1
    cmp rax, 9
    jb failure
    lea rax, [rip + stream]
    mov edx, 9
    call .Lkeystream
    xor ecx, ecx
.Lcompare:
    lea rsi, [rip + input]
    lea rdi, [rip + stream]
    mov al, byte ptr [rsi + rcx]
    xor al, byte ptr [rdi + rcx]
    lea rsi, [rip + expected]
    cmp al, byte ptr [rsi + rcx]
    jne failure
    inc ecx
    cmp ecx, 9
    jne .Lcompare
    jmp success
.size main, .-main
.type success,@function
success:
    lea rdi, [rip + yes]
    call puts
    xor eax, eax
    pop rbx
    ret
.size success, .-success
.type failure,@function
failure:
    lea rdi, [rip + no]
    call puts
    mov eax, 1
    pop rbx
    ret
.size failure, .-failure
.type frame_dummy,@function
frame_dummy:
    jmp .Lframe_end
.Lkeystream:
    mov rbx, rax
    mov r11d, edx
    lea rdi, [rip + state]
    xor ecx, ecx
.Linitialize:
    mov byte ptr [rdi + rcx], cl
    inc ecx
    cmp ecx, 256
    jne .Linitialize
    xor ecx, ecx
    xor esi, esi
    xor r8d, r8d
    lea r10, [rip + key]
.Lschedule:
    movzx eax, byte ptr [rdi + rcx]
    add esi, eax
    movzx edx, byte ptr [r10 + r8]
    add esi, edx
    and esi, 255
    mov dl, byte ptr [rdi + rsi]
    mov byte ptr [rdi + rcx], dl
    mov byte ptr [rdi + rsi], al
    inc r8d
    cmp r8d, 3
    jne .Lkey_next
    xor r8d, r8d
.Lkey_next:
    inc ecx
    cmp ecx, 256
    jne .Lschedule
    xor ecx, ecx
    xor esi, esi
    xor r8d, r8d
.Lgenerate:
    inc ecx
    and ecx, 255
    movzx eax, byte ptr [rdi + rcx]
    add esi, eax
    and esi, 255
    movzx edx, byte ptr [rdi + rsi]
    mov byte ptr [rdi + rcx], dl
    mov byte ptr [rdi + rsi], al
    add eax, edx
    and eax, 255
    mov al, byte ptr [rdi + rax]
    mov byte ptr [rbx + r8], al
    inc r8d
    cmp r8d, r11d
    jne .Lgenerate
    ret
.Lframed:
    push rbp
    mov rbp, rsp
    add rax, 1
    pop rbp
    ret
.Lframe_end:
    ret
.size frame_dummy, .-frame_dummy
.type puts,@function
puts:
    mov rsi, rdi
    xor edx, edx
.Llength:
    cmp byte ptr [rsi + rdx], 0
    je .Lprint
    inc edx
    jmp .Llength
.Lprint:
    mov eax, 1
    mov edi, 1
    syscall
    ret
.size puts, .-puts
.section .rodata
key: .ascii "Key"
expected: .byte 0x98,0xe8,0x18,0xf3,0xd3,0x52,0xa3,0x01,0xcf
yes: .asciz "success\n"
no: .asciz "failure\n"
.bss
.align 16
input: .skip 128
stream: .skip 16
state: .skip 256
.section .note.GNU-stack,"",@progbits
