#!/usr/bin/env bash
# Build linked 32-bit RTTI descriptors without a system C++ runtime.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p target/cpp32-build tests/metadata/cpp32
common=(-O1 -g -fno-inline -ffile-prefix-map="$PWD"=. -fdebug-compilation-dir=.)
for arch in i386 arm thumb; do
    triple=i686-unknown-linux-gnu
    mode=()
    if [ "$arch" != i386 ]; then triple=armv7a-linux-gnueabihf; fi
    if [ "$arch" = thumb ]; then mode=(-mthumb); fi
    clang --target="$triple" "${mode[@]}" -fPIC -c tests/cases/cpp/rtti_runtime.c -o target/cpp32-build/runtime.o
    if [ "$arch" != i386 ]; then
        clang --target="$triple" "${mode[@]}" -fPIC -c tests/cases/cpp/arm_runtime.c -o target/cpp32-build/arm_runtime.o
        ld.lld -shared -soname cpp_runtime.so target/cpp32-build/runtime.o target/cpp32-build/arm_runtime.o -o target/cpp32-build/runtime.so
    else
        ld.lld -shared -soname cpp_runtime.so target/cpp32-build/runtime.o -o target/cpp32-build/runtime.so
    fi
    clang++ --target="$triple" "${mode[@]}" "${common[@]}" -c tests/cases/cpp/rtti.cpp -o target/cpp32-build/input.o
    ld.lld -e single target/cpp32-build/input.o target/cpp32-build/runtime.so -o "tests/metadata/cpp32/rtti.$arch.debug.elf"
    llvm-strip -s "tests/metadata/cpp32/rtti.$arch.debug.elf" -o "tests/metadata/cpp32/rtti.$arch.stripped.elf"
done
lld-link /lib /machine:x86 /def:tests/cases/pe/rtti_imports.def /out:target/cpp32-build/imports.lib
clang++ --target=i686-pc-windows-msvc "${common[@]}" -gdwarf -c tests/cases/cpp/rtti.cpp -o target/cpp32-build/input.obj
lld-link /dll /noentry /nodefaultlib /debug:dwarf /Brepro /safeseh:no /implib:target/cpp32-build/output.lib /out:tests/metadata/cpp32/rtti.x86.debug.dll target/cpp32-build/input.obj target/cpp32-build/imports.lib
llvm-strip -s tests/metadata/cpp32/rtti.x86.debug.dll -o tests/metadata/cpp32/rtti.x86.stripped.dll
