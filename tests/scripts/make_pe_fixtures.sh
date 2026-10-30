#!/usr/bin/env bash
# Build CRT-free Windows x64 DLLs with relocated DWARF and stripped copies.
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p tests/fixtures/metrics target/pe-build
clang --target=x86_64-pc-windows-msvc -c tests/cases/pe/runtime.c -o target/pe-build/runtime.obj
for source in tests/cases/c/*.c; do
  case=$(basename "$source" .c)
  case "$case" in pe64 | shared_pointers | type_library_linux | type_library_windows) continue ;; esac
  for opt in O0 O2; do
    base="tests/fixtures/metrics/$case.win64.$opt"
    clang --target=x86_64-pc-windows-msvc -gdwarf -"$opt" -fno-inline -fno-builtin \
      "-ffile-prefix-map=$PWD=." -fdebug-compilation-dir=. \
      -c "$source" -o target/pe-build/input.obj
    lld-link /dll /noentry /nodefaultlib /debug:dwarf /Brepro \
      /implib:target/pe-build/input.lib /out:"$base.debug.dll" target/pe-build/input.obj target/pe-build/runtime.obj
    llvm-strip --strip-all "$base.debug.dll" -o "$base.stripped.dll"
  done
done

lld-link /lib /machine:x64 /def:tests/cases/pe/imports.def /out:target/pe-build/imports.lib
for opt in O0 O2; do
  base="tests/fixtures/metrics/windows.win64.$opt"
  clang --target=x86_64-pc-windows-msvc -gdwarf -"$opt" -fno-inline -fno-builtin \
    "-ffile-prefix-map=$PWD=." -fdebug-compilation-dir=. \
    -c tests/cases/pe/windows.c -o target/pe-build/windows.obj
  lld-link /dll /noentry /nodefaultlib /debug:dwarf /Brepro \
    /implib:target/pe-build/input.lib /out:"$base.debug.dll" \
    target/pe-build/windows.obj target/pe-build/runtime.obj target/pe-build/imports.lib
  llvm-strip --strip-all "$base.debug.dll" -o "$base.stripped.dll"
done

{
  clang --version | head -1
  lld-link --version
  llvm-strip --version | sed -n '2p'
} > tests/fixtures/pe_toolchain.txt
