#!/usr/bin/env bash
set -euo pipefail
out=${1:?output directory required}
mkdir -p "$out"
source_dir=$(cd "$(dirname "$0")/../data" && pwd)
clang --target=x86_64-unknown-linux-gnu -c "$source_dir/raw_linux.s" -o "$out/raw.o"
ld.lld -e _start "$out/raw.o" -o "$out/raw.elf"
for arch in x86_64 i386 aarch64; do
    clang --target="$arch-unknown-linux-gnu" -c "$source_dir/linux_syscalls.S" -o "$out/$arch.o"
    ld.lld -e io_entry "$out/$arch.o" -o "$out/$arch.elf"
done
cat > "$out/strings.S" <<'ASM'
#ifdef __APPLE__
#define NAME(x) _##x
#else
#define NAME(x) x
#endif
.text
ASM
for direction in forward backward; do
    for width in b w d q; do
        case $width in b) prefix=; add=0;; w) prefix='0x66,'; add=1;; d) prefix=; add=1;; q) prefix='0x48,'; add=1;; esac
        for operation in movs stos lods cmps scas; do
            case $operation in movs) opcode=$((164+add));; stos) opcode=$((170+add));; lods) opcode=$((172+add));; cmps) opcode=$((166+add));; scas) opcode=$((174+add));; esac
            for repeat in once equal unequal; do
                case $repeat in once) rep_prefix=;; equal) rep_prefix='0xf3,';; unequal) rep_prefix='0xf2,';; esac
                name="${operation}_${width}_${repeat}_${direction}"
                cat >> "$out/strings.S" <<ASM
.globl NAME($name)
#ifndef __APPLE__
.type $name,@function
#endif
NAME($name):
    mov %rdx, %rcx
    mov \$1, %eax
    cmp %eax, %eax
ASM
                if [ "$direction" = backward ]; then echo '    std' >> "$out/strings.S"; else echo '    cld' >> "$out/strings.S"; fi
                cat >> "$out/strings.S" <<ASM
    .byte $rep_prefix$prefix$opcode
    setz %r8b
    movzbl %r8b, %r8d
    shl \$32, %r8
    xor %r8, %rax
    shl \$40, %rcx
    xor %rcx, %rax
    cld
    ret
ASM
            done
        done
    done
done
clang --target=x86_64-unknown-linux-gnu -c "$out/strings.S" -o "$out/strings.o"
ld.lld -e movs_b_once_forward "$out/strings.o" -o "$out/strings.elf"
