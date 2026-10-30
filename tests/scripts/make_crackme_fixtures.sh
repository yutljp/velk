#!/usr/bin/env bash
set -euo pipefail
out=${1:?output directory required}
shift
source_dir=$(cd "$(dirname "$0")/../data/crackmes" && pwd)
mkdir -p "$out"
for arch in x86_64 aarch64; do
    clang --target="$arch-unknown-linux-gnu" -O2 -fPIC -ffreestanding -c \
        "$source_dir/../symbolic_streams.c" -o "$out/$arch-imports.o"
    ld.lld -shared "$out/$arch-imports.o" -o "$out/lib$arch-input.so"
    for opt in 0 2; do
        for source in "$source_dir"/*.c; do
            name=$(basename "$source" .c)
            base="$out/$arch-O$opt-$name"
            clang --target="$arch-unknown-linux-gnu" -O"$opt" -g -ffreestanding \
                -fno-stack-protector -fno-optimize-sibling-calls \
                "$@" -c "$source" -o "$base.o"
            ld.lld -e main "$base.o" -L"$out" -l"$arch-input" -o "$base.elf"
            if [ "$(uname -s)" = Linux ]; then
                host_arch=$(uname -m)
                if [ "$host_arch" = arm64 ]; then host_arch=aarch64; fi
                compiler="$arch-linux-gnu-gcc"
                if [ "$arch" = "$host_arch" ]; then compiler=clang; fi
                if command -v "$compiler" >/dev/null; then
                    for linkage in dynamic static; do
                        flags=(-no-pie)
                        if [ "$linkage" = static ]; then flags=(-static); fi
                        "$compiler" -O"$opt" -g -fno-builtin -fno-stack-protector \
                            -fno-optimize-sibling-calls ${flags[@]+"${flags[@]}"} \
                            "$@" "$source" -o "$base-$linkage"
                    done
                fi
            fi
        done
    done
done

compile_protected() {
    local source=$1 object=$2
    if [ "$guard" = tpidr ]; then
        # Apple clang accepts SP_EL0 for guard generation; assemble the same
        # sequence with the userspace thread register instead.
        clang --target="$arch-unknown-linux-gnu" -O"$opt" -g -ffreestanding \
            -fstack-protector-strong -fno-optimize-sibling-calls "${flags[@]}" \
            -S "$source" -o "$object.s"
        sed 's/SP_EL0/TPIDR_EL0/g;s/sp_el0/tpidr_el0/g' "$object.s" > "$object-tpidr.s"
        clang --target="$arch-unknown-linux-gnu" -c "$object-tpidr.s" -o "$object"
    else
        clang --target="$arch-unknown-linux-gnu" -O"$opt" -g -ffreestanding \
            -fstack-protector-strong -fno-optimize-sibling-calls \
            -c "$source" -o "$object"
    fi
}

for arch in x86_64 aarch64 i386; do
    clang --target="$arch-unknown-linux-gnu" -O2 -fPIC -ffreestanding -c \
        "$source_dir/../stack_guard_imports.c" -o "$out/$arch-stack-imports.o"
    ld.lld -shared "$out/$arch-stack-imports.o" -o "$out/lib$arch-stack.so"
    if [ "$arch" = i386 ]; then
        clang --target="$arch-unknown-linux-gnu" -O2 -fPIC -ffreestanding -c \
            "$source_dir/../symbolic_streams.c" -o "$out/$arch-imports.o"
        ld.lld -shared "$out/$arch-imports.o" -o "$out/lib$arch-input.so"
    fi
    for opt in 0 2; do
        guards=(default)
        if [ "$arch" = aarch64 ]; then guards+=(tpidr); fi
        for guard in "${guards[@]}"; do
            flags=()
            suffix=protected
            if [ "$guard" = tpidr ]; then
                flags=(-mstack-protector-guard=sysreg -mstack-protector-guard-reg=sp_el0
                    -mstack-protector-guard-offset=40)
                suffix=protected-tpidr
            fi
            compile_protected "$source_dir/../stack_guard.c" "$out/$arch-O$opt-$suffix-guard.o"
            names=(sum table)
            if [ "$arch" = i386 ]; then names=(sum); fi
            for name in "${names[@]}"; do
                base="$out/$arch-O$opt-$name-$suffix"
                compile_protected "$source_dir/$name.c" "$base.o"
                ld.lld -e main "$base.o" "$out/$arch-O$opt-$suffix-guard.o" \
                    -L"$out" -l"$arch-input" -l"$arch-stack" -o "$base.elf"
            done
        done
        if [ "$arch" = x86_64 ]; then
            for name in sum table; do
                clang -O"$opt" -fno-builtin -fstack-protector-strong \
                    -fno-optimize-sibling-calls "$source_dir/$name.c" \
                    -o "$out/native-O$opt-$name-protected"
            done
        fi
    done
done
