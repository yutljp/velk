#!/usr/bin/env bash
set -euo pipefail
out=${1:?output directory required}
mkdir -p "$out"
source_dir=$(cd "$(dirname "$0")/../data" && pwd)
cat > "$out/sections.ld" <<'LD'
PHDRS { text PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }
SECTIONS {
  . = 0x400000;
  .text : { *(.text*) } :text
  .init : { *(.init) } :text
  .fini : { *(.fini) } :text
  . = 0x600000;
  .data : { *(.data*) *(.bss*) } :data
  . = 0x8001a0;
  .hidden : { *(.hidden) } :NONE
  . = 0x810000;
  .hidden_data : { *(.hidden_data) } :NONE
  /DISCARD/ : { *(.eh_frame*) *(.ARM.exidx*) }
}
LD
cat > "$out/data.S" <<'ASM'
.section .hidden_data,"awx"
.balign 8
.globl executable_data
executable_data:
.zero 32
ASM
for arch in x86_64 i386 aarch64 arm thumb; do
    flags=()
    target=$arch
    if [ "$arch" = arm ] || [ "$arch" = thumb ]; then
        target=armv7
        if [ "$arch" = thumb ]; then flags+=(-mthumb); fi
    fi
    clang --target="$target-unknown-linux-gnu" ${flags[@]+"${flags[@]}"} -O1 -g -ffreestanding -fno-pic -fno-pie \
        -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables \
        -c "$source_dir/section_stores.c" -o "$out/$arch.o"
    clang --target="$target-unknown-linux-gnu" ${flags[@]+"${flags[@]}"} -c "$out/data.S" -o "$out/$arch-data.o"
    ld.lld -T "$out/sections.ld" -e text_stores "$out/$arch.o" "$out/$arch-data.o" -o "$out/$arch.elf"
done
cat > "$out/stack.S" <<'ASM'
.section .hidden,"ax",@progbits
.globl caller_stores
.type caller_stores,@function
caller_stores:
    pushq %rbp
    movq %rsp, %rbp
    movb $0x81, 16(%rbp)
    movw $0x8234, 18(%rbp)
    movl $0x856789ab, 20(%rbp)
    movabsq $0x8123456789abcdef, %rax
    movq %rax, 24(%rbp)
    xorl %eax, %eax
    popq %rbp
    ret
.size caller_stores, .-caller_stores
.globl parameter_stores
.type parameter_stores,@function
parameter_stores:
    movb %dil, 8(%rsp)
    movw %di, 10(%rsp)
    movl %edi, 12(%rsp)
    movq %rdi, 16(%rsp)
    xorl %eax, %eax
    ret
.size parameter_stores, .-parameter_stores
.text
.globl text_caller_stores
.type text_caller_stores,@function
text_caller_stores:
    movb $0x81, 8(%rsp)
    movw $0x8234, 10(%rsp)
    movl $0x856789ab, 12(%rsp)
    movabsq $0x8123456789abcdef, %rax
    movq %rax, 16(%rsp)
    xorl %eax, %eax
    ret
.size text_caller_stores, .-text_caller_stores
ASM
clang --target=x86_64-unknown-linux-gnu -c "$out/stack.S" -o "$out/stack.o"
ld.lld -T "$out/sections.ld" -e caller_stores "$out/stack.o" -o "$out/stack.elf"
