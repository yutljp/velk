#!/bin/sh
set -eu
mkdir -p tests/data/inline_functions target
if [ "$#" -eq 0 ]; then
    set -- clang gcc
fi
for compiler in "$@"; do
    case "$compiler" in
        clang|gcc) ;;
        *) echo 'Expected clang or gcc.' >&2; exit 2 ;;
    esac
    for arch in x86_64 aarch64; do
        for level in 2 3; do
            for suffix in '' .debug; do
                case "$suffix" in
                    .debug) debug_flags=-gdwarf-4 ;;
                    *) debug_flags= ;;
                esac
                object="target/inline_functions.$arch.$compiler.O$level$suffix.o"
                case "$compiler" in
                    clang)
                        clang --target="$arch-linux-gnu" -O"$level" -fno-builtin \
                            -fno-stack-protector $debug_flags -ffile-prefix-map="$PWD"=. \
                            -fdebug-compilation-dir=. -c tests/cases/inline_functions/functions.c \
                            -o "$object"
                        ;;
                    gcc)
                        "$arch-linux-gnu-gcc" -O"$level" -fno-builtin -fno-stack-protector \
                            $debug_flags -ffile-prefix-map="$PWD"=. \
                            -c tests/cases/inline_functions/functions.c -o "$object"
                        ;;
                esac
                case "$arch" in
                    x86_64) emulation=elf_x86_64 ;;
                    aarch64) emulation=aarch64elf ;;
                esac
                ld.lld -m "$emulation" --entry=fill13 \
                    -o "tests/data/inline_functions/$arch.$compiler.O$level$suffix.elf" "$object"
            done
        done
    done
    case "$compiler" in
        clang) clang --version | head -1 > tests/data/inline_functions/clang.txt ;;
        gcc)
            x86_64-linux-gnu-gcc --version | head -1 > tests/data/inline_functions/gcc.txt
            aarch64-linux-gnu-gcc --version | head -1 >> tests/data/inline_functions/gcc.txt
            ;;
    esac
done
