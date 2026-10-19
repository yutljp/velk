#!/usr/bin/env bash
# Build the regression fixtures.
#   sources: tests/cases/ (tracked)          output: tests/out/ (untracked, ignored)
# Cases whose tools are missing are skipped with a warning; the rest are still built.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=${VELK_OUT:-tests/out}
CASES=tests/cases
mkdir -p "$OUT"
OUT_ABS=$(cd "$OUT" && pwd)

# Tools are looked up on PATH with `which`. Tools not on PATH can be set
# with these environment variables:
#
#   CLANG / CXX / LD_LLD / LLD_LINK / LLVM_STRIP / LLVM_OBJCOPY / RUSTC / GO_BIN
#
which_path() {
  which "$1" 2>/dev/null || true
}
resolve() {  # resolve <env-var-name> <command>
  local override=$1 name=$2 value
  eval "value=\${$override:-}"
  if [ -z "$value" ]; then value=$(which_path "$name"); fi
  printf '%s' "$value"
}

# Skip the rebuild when the toolchain is unchanged and every output exists.
# VELK_FORCE_FIXTURES=1 forces a rebuild.
fingerprint() {
  printf '%s\n' "$CLANG" "$CXX" "$LD_LLD" "$LLD_LINK" "$STRIP" "$OBJCOPY" "$RUSTC" "$GO_BIN"
  "$CLANG" --version 2>/dev/null | head -1
}
up_to_date() {
  [ "${VELK_FORCE_FIXTURES:-0}" = 1 ] && return 1
  [ -f "$OUT/.stamp" ] && [ -f "$OUT/.manifest" ] || return 1
  [ "$(cat "$OUT/.stamp")" = "$(fingerprint)" ] || return 1
  # Rebuild if any source or this script is newer than the stamp.
  [ -z "$(find "$CASES" -type f -newer "$OUT/.stamp" -print -quit 2>/dev/null)" ] || return 1
  [ "$0" -nt "$OUT/.stamp" ] && return 1
  while IFS= read -r name; do
    [ -z "$name" ] && continue
    [ -e "$OUT/$name" ] || return 1
  done < "$OUT/.manifest"
  return 0
}

CXX=$(resolve CXX clang++)
LD_LLD=$(resolve LD_LLD ld.lld)
LLD_LINK=$(resolve LLD_LINK lld-link)
STRIP=$(resolve LLVM_STRIP llvm-strip)
OBJCOPY=$(resolve LLVM_OBJCOPY llvm-objcopy)
RUSTC=$(resolve RUSTC rustc)
GO_BIN=$(resolve GO_BIN go)

CLANG=$(resolve CLANG clang)
if [ -z "$CLANG" ]; then
  echo "skip: clang not found (add it to PATH or set CLANG=)" >&2
  exit 1
fi


if up_to_date; then
  echo "fixtures: $(grep -c . "$OUT/.manifest") up to date in $OUT (VELK_FORCE_FIXTURES=1 to rebuild)"
  exit 0
fi

built=()
skipped=()

# --- PE64 (x86-64, no CRT) ---
"$CLANG" --target=x86_64-pc-windows-msvc -ffreestanding -O2 -c \
  "$CASES/c/pe64.c" -o "$OUT/pe64.obj"
if [ -n "$LLD_LINK" ]; then
  "$LLD_LINK" /out:"$OUT/pe64.exe" /entry:entry /nodefaultlib /subsystem:console \
    /export:reg_add /export:reg_mul /export:reg_sign /export:reg_max \
    /export:reg_negative /export:reg_abs /export:msg_first /export:reg_div \
    /export:reg_mod "$OUT/pe64.obj"
else
  echo "warn: lld-link not found (PATH or LLD_LINK=); PE fixture limited to COFF object" >&2
  skipped+=(pe64-link)
  cp "$OUT/pe64.obj" "$OUT/pe64.exe"
fi
built+=(pe64.exe)

# --- basic AArch64 / x86-64 objects ---
"$CLANG" -target aarch64-unknown-linux-gnu -O2 -c "$CASES/c/arith_mixed.c" -o "$OUT/arm64.o"
"$CLANG" -target aarch64-unknown-linux-gnu -O2 -c "$CASES/c/divmod_a64.c"  -o "$OUT/arm64_div.o"
"$CLANG" -target aarch64-unknown-linux-gnu -O2 -c "$CASES/c/alt_names.c"   -o "$OUT/alt.o"
# Apple clang builds Mach-O with -arch; other clang builds ELF with --target
# (the dec helper in the tests handles the leading underscore on symbol names).
if ! "$CLANG" -arch x86_64 -O2 -c "$CASES/c/divmod_x64.c" -o "$OUT/x64_div.o" 2>/dev/null; then
  "$CLANG" --target=x86_64-unknown-linux-gnu -O2 -c "$CASES/c/divmod_x64.c" -o "$OUT/x64_div.o"
fi
built+=(arm64.o arm64_div.o alt.o x64_div.o)

# --- loops (-O2 and -O0) ---
"$CLANG" -target aarch64-unknown-linux-gnu -O2 -c "$CASES/c/loops.c" -o "$OUT/arm64_loops.o"
"$CLANG" -target aarch64-unknown-linux-gnu -O0 -c "$CASES/c/loops.c" -o "$OUT/arm64_loops0.o"
"$CLANG" -target x86_64-unknown-linux-gnu  -O2 -c "$CASES/c/loops.c" -o "$OUT/x64_loops.o"
built+=(arm64_loops.o arm64_loops0.o x64_loops.o)

# --- linked ELF (string references, value-table switch, jump table) ---
if [ -n "$LD_LLD" ]; then
  for case in strings switch_value_table switch_jumptable; do
    "$CLANG" -target aarch64-unknown-linux-gnu -O2 -c "$CASES/c/$case.c" -o "$OUT/$case.o"
  done
  "$LD_LLD" -m aarch64elf -e pick -o "$OUT/arm64_linked.elf"   "$OUT/strings.o"
  "$LD_LLD" -m aarch64elf -e dispatch -o "$OUT/arm64_switch.elf" "$OUT/switch_value_table.o"
  "$LD_LLD" -m aarch64elf -e d7 -o "$OUT/arm64_jumptable.elf"  "$OUT/switch_jumptable.o"
  built+=(arm64_linked.elf arm64_switch.elf arm64_jumptable.elf)
else
  echo "warn: ld.lld not found (PATH or LD_LLD=); linked ELF fixtures skipped" >&2
  skipped+=(linked-elf)
fi

# --- DWARF (names, types, members) and stripped images ---
if [ -n "$LD_LLD" ]; then
  "$CLANG" -g -target aarch64-unknown-linux-gnu -O2 -c "$CASES/c/arith_mixed.c" -o "$OUT/arm64_debug.o"
  "$LD_LLD" -m aarch64elf -e sum3 -o "$OUT/arm64_debug.elf" "$OUT/arm64_debug.o"
  built+=(arm64_debug.o arm64_debug.elf)
  if [ -n "$OBJCOPY" ]; then
    "$OBJCOPY" --remove-section=.symtab --remove-section=.strtab \
      "$OUT/arm64_debug.elf" "$OUT/arm64_debug_stripped.elf"
    built+=(arm64_debug_stripped.elf)
  fi
fi

# --- stripped objects (function discovery: ret, tail calls, indirect tail calls) ---
if [ -n "$STRIP" ]; then
  "$STRIP" -s "$OUT/arm64_loops.o" -o "$OUT/arm64_loops_stripped.o"
  "$STRIP" -s "$OUT/x64_loops.o"   -o "$OUT/x64_loops_stripped.o"
  for case in tail_calls tail_indirect; do
    "$CLANG" -target aarch64-unknown-linux-gnu -O2 -c "$CASES/c/$case.c" -o "$OUT/$case.o"
    "$STRIP" -s "$OUT/$case.o" -o "$OUT/${case}_stripped.o"
  done
  built+=(arm64_loops_stripped.o x64_loops_stripped.o tail_calls_stripped.o tail_indirect_stripped.o)
else
  echo "warn: llvm-strip not found (PATH or LLVM_STRIP=); stripped fixtures skipped" >&2
  skipped+=(stripped)
fi

# --- difficulty ladder (L0/L1/L2/L4/L6 for both ISAs, L5 linked) ---
# L4 uses -O1: at -O2 the loops are vectorized into SIMD code, which
# defeats the memory-access recovery test.
for case in l0_arith l1_branch l2_loop l6_abi; do
  "$CLANG" -target aarch64-unknown-linux-gnu -O2 -c "$CASES/c/$case.c" -o "$OUT/${case}_a64.o"
  "$CLANG" -target x86_64-unknown-linux-gnu  -O2 -c "$CASES/c/$case.c" -o "$OUT/${case}_x64.o"
  built+=("${case}_a64.o" "${case}_x64.o")
done
for isa in aarch64 x86_64; do
  suffix=a64; [ "$isa" = x86_64 ] && suffix=x64
  "$CLANG" -target "$isa-unknown-linux-gnu" -O1 -c "$CASES/c/l4_memory.c" -o "$OUT/l4_memory_$suffix.o"
  built+=("l4_memory_$suffix.o")
done
if [ -n "$LD_LLD" ]; then
  "$CLANG" -target aarch64-unknown-linux-gnu -O2 -c "$CASES/c/l5_switch.c" -o "$OUT/l5_switch.o"
  "$LD_LLD" -m aarch64elf -e dense -o "$OUT/l5_switch.elf" "$OUT/l5_switch.o"
  built+=(l5_switch.elf)
fi

# --- Go (names from pclntab; only if Go is installed) ---
if [ -n "$GO_BIN" ] && [ -x "$GO_BIN" ]; then
  ( cd "$CASES/go" && GO111MODULE=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      "$GO_BIN" build -trimpath -ldflags "-s -w" -o "$OUT_ABS/go_stripped" add.go )
  ( cd "$CASES/go" && GO111MODULE=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      "$GO_BIN" build -trimpath -ldflags "-s -w" -o "$OUT_ABS/go_probe" probe.go )
  built+=(go_stripped go_probe)
else
  echo "warn: go not found (add it to PATH or set GO_BIN=); Go fixtures skipped" >&2
  skipped+=(go)
fi

# --- Rust / C++ (demangling; only if the toolchain is installed) ---
if [ -n "$RUSTC" ] && [ -x "$RUSTC" ]; then
  # --crate-name keeps the symbol namespace stable across file renames.
  "$RUSTC" -O --crate-name rust_demo  -o "$OUT/rust_demo"  "$CASES/rust/add.rs"
  "$RUSTC" -O --crate-name rust_probe -o "$OUT/rust_probe" "$CASES/rust/probe.rs"
  built+=(rust_demo rust_probe)
  if [ -n "$STRIP" ]; then
    "$STRIP" -s "$OUT/rust_probe" -o "$OUT/rust_probe_stripped"
    built+=(rust_probe_stripped)
  fi
else
  echo "warn: rustc not found (PATH or RUSTC=); Rust fixtures skipped" >&2
  skipped+=(rust)
fi

if [ -n "$CXX" ] && [ -x "$CXX" ]; then
  "$CXX" -O2 -c "$CASES/cpp/namespace.cpp" -o "$OUT/cpp_demo.o"
  built+=(cpp_demo.o)
fi

# --- large input (loader/scan performance regression; 20 MB of padding) ---
if [ ! -f "$OUT/arm64_big.o" ] || [ "$OUT/arm64.o" -nt "$OUT/arm64_big.o" ]; then
  cat "$OUT/arm64.o" > "$OUT/arm64_big.o"
  dd if=/dev/zero bs=1048576 count=20 >> "$OUT/arm64_big.o" 2>/dev/null
fi

# Record which compiler built the fixtures, for calibrating assertions.
"$CLANG" --version 2>/dev/null | head -1 > "$OUT/clang.txt" || true
printf 'clang: %s\n' "$CLANG" >> "$OUT/clang.txt"
cp "$OUT/clang.txt" "$OUT/toolchain.txt"

# Tells ladder.sh which fixtures were not built, so they are reported as SKIP.
printf '%s\n' "${skipped[@]:-}" | sed '/^$/d' > "$OUT/skipped.txt"

printf '%s\n' "${built[@]:-}" | sed '/^$/d' > "$OUT/.manifest"
fingerprint > "$OUT/.stamp"
echo "fixtures: ${#built[@]} built in $OUT"
if [ ${#skipped[@]} -gt 0 ]; then
  echo "skipped: ${skipped[*]} (matching ladder cases will be SKIP)"
fi
