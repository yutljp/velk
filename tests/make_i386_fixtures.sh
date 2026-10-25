#!/usr/bin/env bash
# Build CRT-free ELF32 and PE32 fixtures with debug and stripped copies.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p target/i386-build tests/fixtures/metrics
for source in tests/cases/c/l0_arith.c tests/cases/c/l1_branch.c; do
  case=$(basename "$source" .c)
  for opt in O0 O2; do
    base="tests/fixtures/metrics/$case.i386.$opt"
    clang --target=i686-linux-gnu -m32 -gdwarf -"$opt" -fno-inline -fno-builtin -fno-pic \
      "-ffile-prefix-map=$PWD=." -fdebug-compilation-dir=. -c "$source" -o target/i386-build/input.o
    ld.lld -m elf_i386 -shared -z notext target/i386-build/input.o -o "$base.debug.elf"
    llvm-strip --strip-all "$base.debug.elf" -o "$base.stripped.elf"
    base="tests/fixtures/metrics/$case.win32.$opt"
    clang --target=i686-pc-windows-msvc -gdwarf -"$opt" -fno-inline -fno-builtin \
      "-ffile-prefix-map=$PWD=." -fdebug-compilation-dir=. -c "$source" -o target/i386-build/input.obj
    exports=()
    while read -r name; do exports+=("/export:$name"); done < <(llvm-nm --defined-only --extern-only --format=just-symbols target/i386-build/input.obj | sed 's/^_//')
    lld-link /dll /noentry /nodefaultlib /debug:dwarf /Brepro \
      /implib:target/i386-build/input.lib /out:"$base.debug.dll" target/i386-build/input.obj "${exports[@]}"
    llvm-strip --strip-all "$base.debug.dll" -o "$base.stripped.dll"
  done
done
for opt in O0 O2; do
  base="tests/fixtures/metrics/conventions.win32.$opt"
  clang --target=i686-pc-windows-msvc -gdwarf -"$opt" -fno-inline -fno-builtin \
    "-ffile-prefix-map=$PWD=." -fdebug-compilation-dir=. \
    -c tests/cases/i386/conventions.c -o target/i386-build/conventions.obj
  lld-link /dll /noentry /nodefaultlib /debug:dwarf /Brepro \
    /implib:target/i386-build/input.lib /out:"$base.debug.dll" target/i386-build/conventions.obj
  llvm-strip --strip-all "$base.debug.dll" -o "$base.stripped.dll"
done

lld-link /lib /machine:x86 /def:tests/cases/i386/imports.def /out:target/i386-build/imports.lib
for opt in O0 O2; do
  base="tests/fixtures/metrics/imports.win32.$opt"
  clang --target=i686-pc-windows-msvc -gdwarf -"$opt" -fno-inline -fno-builtin \
    "-ffile-prefix-map=$PWD=." -fdebug-compilation-dir=. \
    -c tests/cases/i386/imports.c -o target/i386-build/imports.obj
  lld-link /dll /noentry /nodefaultlib /debug:dwarf /Brepro \
    /implib:target/i386-build/input.lib /out:"$base.debug.dll" \
    target/i386-build/imports.obj target/i386-build/imports.lib
  llvm-strip --strip-all "$base.debug.dll" -o "$base.stripped.dll"
  base="tests/fixtures/metrics/relocations.i386.$opt"
  clang --target=i686-linux-gnu -m32 -gdwarf -"$opt" -fPIC -fno-inline -fno-builtin \
    "-ffile-prefix-map=$PWD=." -fdebug-compilation-dir=. \
    -c tests/cases/i386/relocations.c -o target/i386-build/relocations.o
  ld.lld -m elf_i386 -shared target/i386-build/relocations.o -o "$base.debug.elf"
  llvm-strip --strip-all "$base.debug.elf" -o "$base.stripped.elf"
done

{
  clang --version | head -1
  lld-link --version
  llvm-strip --version | sed -n '2p'
} > tests/fixtures/i386_toolchain.txt

llvm-dlltool -m i386 -k -d tests/cases/i386/windows_types.def -l target/i386-build/windows_types.lib
clang --target=i686-pc-windows-msvc -O2 -fno-builtin -c tests/cases/i386/windows_types.c -o target/i386-build/windows_types.obj
lld-link /dll /noentry /nodefaultlib /Brepro /implib:target/i386-build/windows_types_export.lib \
  /out:tests/fixtures/windows_types.pe32.dll target/i386-build/windows_types.obj target/i386-build/windows_types.lib
