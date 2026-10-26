#!/usr/bin/env bash
# Build C++ RTTI and exception tables for the three 64-bit object formats.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p target/cpp-build tests/fixtures/cpp
source=tests/cases/cpp/rtti.cpp
common=(-O1 -g -fno-inline -ffile-prefix-map="$PWD"=. -fdebug-compilation-dir=.)
clang --target=x86_64-unknown-linux-gnu -fPIC -c tests/cases/cpp/rtti_runtime.c -o target/cpp-build/runtime.o
ld.lld -shared -soname cpp_runtime.so target/cpp-build/runtime.o -o target/cpp-build/cpp_runtime.so
clang++ --target=x86_64-unknown-linux-gnu "${common[@]}" -c "$source" -o target/cpp-build/input.o
ld.lld -e single target/cpp-build/input.o target/cpp-build/cpp_runtime.so -o tests/fixtures/cpp/rtti.debug.elf
llvm-strip -s tests/fixtures/cpp/rtti.debug.elf -o tests/fixtures/cpp/rtti.stripped.elf
if command -v lld-link >/dev/null; then
    lld-link /lib /machine:x64 /def:tests/cases/pe/rtti_imports.def /out:target/cpp-build/imports.lib
    clang++ --target=x86_64-pc-windows-msvc "${common[@]}" -gdwarf -c "$source" -o target/cpp-build/input.obj
    lld-link /dll /noentry /nodefaultlib /debug:dwarf /Brepro /implib:target/cpp-build/output.lib /out:tests/fixtures/cpp/rtti.debug.dll target/cpp-build/input.obj target/cpp-build/imports.lib
    llvm-strip -s tests/fixtures/cpp/rtti.debug.dll -o tests/fixtures/cpp/rtti.stripped.dll
fi
if [ "$(uname -s)" = Darwin ]; then
    clang++ "${common[@]}" -fvisibility=hidden -c "$source" -o target/cpp-build/input.macho.o
    clang++ -dynamiclib -Wl,-oso_prefix,"$PWD/" -Wl,-no_fixup_chains -Wl,-undefined,dynamic_lookup target/cpp-build/input.macho.o -o tests/fixtures/cpp/rtti.debug.dylib
    strip -x -S tests/fixtures/cpp/rtti.debug.dylib -o tests/fixtures/cpp/rtti.stripped.dylib
fi
