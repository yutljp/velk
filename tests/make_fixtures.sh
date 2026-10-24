#!/usr/bin/env bash
# Build the checked-in test fixtures from tests/cases/ into tests/fixtures/.
# Run it only in the reference container, so every machine tests the same bytes:
#
#   docker compose run --rm fixtures
#
# Every tool is required; a missing one is an error, not a skip.
set -euo pipefail
cd "$(dirname "$0")/.."

ROOT=$(pwd)
OUT=tests/fixtures
CASES=tests/cases

require() {
  command -v "$1" >/dev/null || { echo "error: $1 not found" >&2; exit 1; }
}
for tool in clang clang++ gcc strip ld.lld lld-link llvm-strip llvm-objcopy rustc go strings; do
  require "$tool"
done

rm -rf "$OUT"
mkdir -p "$OUT/metrics"

# Build paths must not reach the fixtures.
CC=(clang "-ffile-prefix-map=$ROOT=.")
CXX=(clang++ "-ffile-prefix-map=$ROOT=.")
RUSTC=(rustc "--remap-path-prefix=$ROOT=.")
A64=--target=aarch64-unknown-linux-gnu
X64=--target=x86_64-unknown-linux-gnu

# PE64 without a C runtime; the timestamp options keep the output reproducible.
"${CC[@]}" --target=x86_64-pc-windows-msvc -ffreestanding -mno-incremental-linker-compatible -O2 -c "$CASES/c/pe64.c" -o "$OUT/pe64.obj"
lld-link /out:"$OUT/pe64.exe" /entry:entry /nodefaultlib /subsystem:console /Brepro \
  /export:reg_add /export:reg_mul /export:reg_sign /export:reg_max \
  /export:reg_negative /export:reg_abs /export:msg_first /export:reg_div \
  /export:reg_mod "$OUT/pe64.obj"
rm -f "$OUT/pe64.lib" "$OUT/pe64.exp"

# Basic objects.
"${CC[@]}" $A64 -O2 -c "$CASES/c/arith_mixed.c" -o "$OUT/arm64.o"
"${CC[@]}" $A64 -O2 -c "$CASES/c/divmod_a64.c" -o "$OUT/arm64_div.o"
"${CC[@]}" $A64 -O2 -c "$CASES/c/alt_names.c" -o "$OUT/alt.o"
"${CC[@]}" $X64 -O2 -c "$CASES/c/divmod_x64.c" -o "$OUT/x64_div.o"

# Mach-O objects; executables would need a macOS SDK.
"${CC[@]}" --target=x86_64-apple-macos13 -O2 -c "$CASES/c/divmod_x64.c" -o "$OUT/x64_div_macho.o"
"${CC[@]}" --target=arm64-apple-macos13 -O2 -c "$CASES/c/arith_mixed.c" -o "$OUT/arm64_macho.o"

# Loops at -O2 and -O0.
"${CC[@]}" $A64 -O2 -c "$CASES/c/loops.c" -o "$OUT/arm64_loops.o"
"${CC[@]}" $A64 -O0 -c "$CASES/c/loops.c" -o "$OUT/arm64_loops0.o"
"${CC[@]}" $X64 -O2 -c "$CASES/c/loops.c" -o "$OUT/x64_loops.o"

# Linked ELF: string references, value-table switch, jump table.
for case in strings switch_value_table switch_jumptable; do
  "${CC[@]}" $A64 -O2 -c "$CASES/c/$case.c" -o "$OUT/$case.o"
done
ld.lld -m aarch64elf -e pick -o "$OUT/arm64_linked.elf" "$OUT/strings.o"
ld.lld -m aarch64elf -e dispatch -o "$OUT/arm64_switch.elf" "$OUT/switch_value_table.o"
ld.lld -m aarch64elf -e d7 -o "$OUT/arm64_jumptable.elf" "$OUT/switch_jumptable.o"
"${CC[@]}" $X64 -O2 -c "$CASES/c/switch_jumptable.c" -o "$OUT/switch_jumptable_x64.o"

# Function addresses used as values, resolved by linking.
"${CC[@]}" $A64 -O2 -c "$CASES/c/calls.c" -o "$OUT/calls_a64.o"
ld.lld -m aarch64elf -e pick_op -o "$OUT/calls_a64.elf" "$OUT/calls_a64.o"

# A shared library: dynamic relocations number the dynamic symbols.
"${CC[@]}" $X64 -O1 -fPIC -c "$CASES/c/shared_pointers.c" -o "$OUT/shared_pointers_x64.o"
ld.lld -shared -o "$OUT/shared_pointers_x64.so" "$OUT/shared_pointers_x64.o"
rm "$OUT/shared_pointers_x64.o"

# DWARF names, types and members, and the same image without symbols.
"${CC[@]}" -g $A64 -O2 -c "$CASES/c/arith_mixed.c" -o "$OUT/arm64_debug.o"
ld.lld -m aarch64elf -e sum3 -o "$OUT/arm64_debug.elf" "$OUT/arm64_debug.o"
llvm-objcopy --remove-section=.symtab --remove-section=.strtab \
  "$OUT/arm64_debug.elf" "$OUT/arm64_debug_stripped.elf"

for isa in a64 x64; do
  target=$A64; emulation=aarch64elf
  [ "$isa" = x64 ] && target=$X64 && emulation=elf_x86_64
  "${CC[@]}" -g $target -O0 -c "$CASES/dwarf/member_types.c" -o "$OUT/member_types_$isa.o"
  ld.lld -m "$emulation" -e read_outer -o "$OUT/member_types_$isa.elf" "$OUT/member_types_$isa.o"
  rm "$OUT/member_types_$isa.o"
done

# Stripped objects: function discovery after returns, tail calls and indirect tail calls.
llvm-strip -s "$OUT/arm64_loops.o" -o "$OUT/arm64_loops_stripped.o"
llvm-strip -s "$OUT/x64_loops.o" -o "$OUT/x64_loops_stripped.o"
for case in tail_calls tail_indirect; do
  "${CC[@]}" $A64 -O2 -c "$CASES/c/$case.c" -o "$OUT/$case.o"
  llvm-strip -s "$OUT/$case.o" -o "$OUT/${case}_stripped.o"
done

# Difficulty ladder. L4 uses -O1 because -O2 vectorizes its loops.
for case in l0_arith l1_branch l2_loop l6_abi; do
  "${CC[@]}" $A64 -O2 -c "$CASES/c/$case.c" -o "$OUT/${case}_a64.o"
  "${CC[@]}" $X64 -O2 -c "$CASES/c/$case.c" -o "$OUT/${case}_x64.o"
done
"${CC[@]}" $A64 -O1 -c "$CASES/c/l4_memory.c" -o "$OUT/l4_memory_a64.o"
"${CC[@]}" $X64 -O1 -c "$CASES/c/l4_memory.c" -o "$OUT/l4_memory_x64.o"
"${CC[@]}" $A64 -O2 -c "$CASES/c/l5_switch.c" -o "$OUT/l5_switch.o"
ld.lld -m aarch64elf -e dense -o "$OUT/l5_switch.elf" "$OUT/l5_switch.o"

# Go function names from pclntab.
for case in add probe; do
  name=go_probe; [ "$case" = add ] && name=go_stripped
  ( cd "$CASES/go" && GO111MODULE=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -ldflags "-s -w" -o "$ROOT/$OUT/$name" "$case.go" )
done

# Rust and C++ demangling.
"${RUSTC[@]}" -O --crate-name rust_demo -o "$OUT/rust_demo" "$CASES/rust/add.rs"
# GCC moves unlikely paths into cold fragments with frame descriptions of their own.
gcc "-ffile-prefix-map=$ROOT=." -O2 -o "$OUT/cold_gcc" "$CASES/gcc/cold.c"
strip -s "$OUT/cold_gcc" -o "$OUT/cold_gcc_stripped"

"${RUSTC[@]}" -O --crate-name rust_probe -o "$OUT/rust_probe" "$CASES/rust/probe.rs"
llvm-strip -s "$OUT/rust_probe" -o "$OUT/rust_probe_stripped"
"${CXX[@]}" $A64 -O2 -c "$CASES/cpp/namespace.cpp" -o "$OUT/cpp_demo.o"
"${CXX[@]}" $A64 -O2 -c "$CASES/cpp/classes.cpp" -o "$OUT/cpp_classes_a64.o"
"${CXX[@]}" $X64 -O2 -c "$CASES/cpp/classes.cpp" -o "$OUT/cpp_classes_x64.o"
# Virtual calls, linked so the tables hold the functions' addresses, and
# without symbols, where the tables are found from the code alone.
for isa in a64 x64; do
  target=$A64; emulation=aarch64elf
  [ "$isa" = x64 ] && target=$X64 && emulation=elf_x86_64
  "${CXX[@]}" $target -O2 -fno-rtti -fno-exceptions -c "$CASES/cpp/virtual.cpp" -o "$OUT/cpp_virtual_$isa.o"
  ld.lld -m "$emulation" -e _Z11square_areai -o "$OUT/cpp_virtual_$isa.elf" "$OUT/cpp_virtual_$isa.o"
  rm "$OUT/cpp_virtual_$isa.o"
  llvm-strip -s "$OUT/cpp_virtual_$isa.elf" -o "$OUT/cpp_virtual_${isa}_stripped.elf"
done

# Ground truth for the recovery metrics: each C case linked with debug info,
# so the DWARF is relocated, and the same executable without symbols or debug
# info, for both ISAs at -O0 and -O2.
for source in "$CASES"/c/*.c; do
  case=$(basename "$source" .c)
  case "$case" in pe64 | shared_pointers) continue ;; esac
  for isa in aarch64 x86_64; do
    emulation=aarch64elf; [ "$isa" = x86_64 ] && emulation=elf_x86_64
    for opt in O0 O2; do
      base="$OUT/metrics/$case.$isa.$opt"
      "${CC[@]}" -g "--target=$isa-unknown-linux-gnu" "-$opt" -fno-inline -c "$source" -o "$base.o"
      ld.lld -m "$emulation" --entry=0 --unresolved-symbols=ignore-all -o "$base.debug.elf" "$base.o"
      rm "$base.o"
      llvm-objcopy --strip-all "$base.debug.elf" "$base.stripped.elf"
    done
  done
done

bash tests/make_pe_fixtures.sh

{
  echo "uname: $(uname -srm)"
  clang --version | head -1
  gcc --version | head -1
  ld.lld --version | head -1
  rustc --version
  go version
} > "$OUT/toolchain.txt"

# Refuse to keep fixtures that mention the build machine.
leaks=$(grep -rlaF -e "$ROOT" -e "$HOME" "$OUT" || true)
if [ -n "$leaks" ]; then
  echo "error: build paths found in:" >&2
  echo "$leaks" >&2
  exit 1
fi
echo "fixtures: $(find "$OUT" -type f | wc -l | tr -d ' ') files in $OUT"
