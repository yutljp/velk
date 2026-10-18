#!/usr/bin/env bash
# 回帰フィクスチャ生成。
#   ソース: tests/cases/ (**追跡**)          生成物: tests/out/ (**未追跡・ignore**)
# 必要なツールが無いケースは警告して飛ばす(残りは生成する)。
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=tests/out
CASES=tests/cases
mkdir -p "$OUT"

if ! command -v clang >/dev/null 2>&1; then
  echo "skip: clang not found" >&2
  exit 1
fi

# llvm-strip / llvm-objcopy は PATH か Homebrew の LLVM から探す。
# Homebrew の LLVM は PATH に無いことが多いので、prefix を自分で探す
# (Apple Silicon と Intel の両方、brew が無い環境も想定)。
brew_llvm_bin() {
  local prefix
  if command -v brew >/dev/null 2>&1; then
    prefix=$(brew --prefix llvm 2>/dev/null || true)
    [ -n "$prefix" ] && [ -d "$prefix/bin" ] && { printf '%s' "$prefix/bin"; return; }
  fi
  for prefix in /opt/homebrew/opt/llvm /usr/local/opt/llvm /usr/lib/llvm-*/bin; do
    [ -x "$prefix/bin/$1" ] && { printf '%s' "$prefix/bin"; return; }
    [ -x "$prefix/$1" ] && { printf '%s' "$prefix"; return; }
  done
}
find_tool() {
  local name=$1 path fallback
  path=$(command -v "$name" || true)
  if [ -z "$path" ]; then
    fallback=$(brew_llvm_bin "$name")
    [ -n "$fallback" ] && path="$fallback/$name"
  fi
  printf '%s' "$path"
}
STRIP=${LLVM_STRIP:-$(find_tool llvm-strip)}
OBJCOPY=${LLVM_OBJCOPY:-$(find_tool llvm-objcopy)}

# 生成できたもの・飛ばしたものを最後に一覧する。
built=()
skipped=()

# --- PE64 (x86-64, CRT 非依存) ---
clang --target=x86_64-pc-windows-msvc -ffreestanding -O2 -c \
  "$CASES/c/pe64.c" -o "$OUT/pe64.obj"
if command -v lld-link >/dev/null 2>&1; then
  lld-link /out:"$OUT/pe64.exe" /entry:entry /nodefaultlib /subsystem:console \
    /export:reg_add /export:reg_mul /export:reg_sign /export:reg_max \
    /export:reg_negative /export:reg_abs /export:msg_first /export:reg_div \
    /export:reg_mod "$OUT/pe64.obj"
else
  echo "warn: lld-link not found; PE fixture limited to COFF object" >&2
  skipped+=(pe64-link)
  cp "$OUT/pe64.obj" "$OUT/pe64.exe"
fi
built+=(pe64.exe)

# --- AArch64 / x86-64 の基本オブジェクト ---
clang -target aarch64-unknown-linux-gnu -O2 -c "$CASES/c/arith_mixed.c" -o "$OUT/arm64.o"
clang -target aarch64-unknown-linux-gnu -O2 -c "$CASES/c/divmod_a64.c"  -o "$OUT/arm64_div.o"
clang -target aarch64-unknown-linux-gnu -O2 -c "$CASES/c/alt_names.c"   -o "$OUT/alt.o"
clang -arch x86_64 -O2 -c "$CASES/c/divmod_x64.c" -o "$OUT/x64_div.o"
built+=(arm64.o arm64_div.o alt.o x64_div.o)

# --- ループ(-O2 と -O0) ---
clang -target aarch64-unknown-linux-gnu -O2 -c "$CASES/c/loops.c" -o "$OUT/arm64_loops.o"
clang -target aarch64-unknown-linux-gnu -O0 -c "$CASES/c/loops.c" -o "$OUT/arm64_loops0.o"
clang -target x86_64-unknown-linux-gnu  -O2 -c "$CASES/c/loops.c" -o "$OUT/x64_loops.o"
built+=(arm64_loops.o arm64_loops0.o x64_loops.o)

# --- リンク済み ELF(文字列参照・値テーブル switch・ジャンプテーブル) ---
if command -v ld.lld >/dev/null 2>&1; then
  for case in strings switch_value_table switch_jumptable; do
    clang -target aarch64-unknown-linux-gnu -O2 -c "$CASES/c/$case.c" -o "$OUT/$case.o"
  done
  ld.lld -m aarch64elf -e pick -o "$OUT/arm64_linked.elf"   "$OUT/strings.o"
  ld.lld -m aarch64elf -e dispatch -o "$OUT/arm64_switch.elf" "$OUT/switch_value_table.o"
  ld.lld -m aarch64elf -e d7 -o "$OUT/arm64_jumptable.elf"  "$OUT/switch_jumptable.o"
  built+=(arm64_linked.elf arm64_switch.elf arm64_jumptable.elf)
else
  echo "warn: ld.lld not found; linked ELF fixtures skipped" >&2
  skipped+=(linked-elf)
fi

# --- DWARF(名前・型・メンバ)と stripped 像 ---
if command -v ld.lld >/dev/null 2>&1; then
  clang -g -target aarch64-unknown-linux-gnu -O2 -c "$CASES/c/arith_mixed.c" -o "$OUT/arm64_debug.o"
  ld.lld -m aarch64elf -e sum3 -o "$OUT/arm64_debug.elf" "$OUT/arm64_debug.o"
  built+=(arm64_debug.o arm64_debug.elf)
  if [ -n "$OBJCOPY" ]; then
    "$OBJCOPY" --remove-section=.symtab --remove-section=.strtab \
      "$OUT/arm64_debug.elf" "$OUT/arm64_debug_stripped.elf"
    built+=(arm64_debug_stripped.elf)
  fi
fi

# --- stripped オブジェクト(関数発見: ret・テールコール・間接テールコール) ---
if [ -n "$STRIP" ]; then
  "$STRIP" -s "$OUT/arm64_loops.o" -o "$OUT/arm64_loops_stripped.o"
  "$STRIP" -s "$OUT/x64_loops.o"   -o "$OUT/x64_loops_stripped.o"
  for case in tail_calls tail_indirect; do
    clang -target aarch64-unknown-linux-gnu -O2 -c "$CASES/c/$case.c" -o "$OUT/$case.o"
    "$STRIP" -s "$OUT/$case.o" -o "$OUT/${case}_stripped.o"
  done
  built+=(arm64_loops_stripped.o x64_loops_stripped.o tail_calls_stripped.o tail_indirect_stripped.o)
else
  echo "warn: llvm-strip not found; stripped fixtures skipped" >&2
  skipped+=(stripped)
fi

# --- 難易度ラダー用(L0/L1/L2/L4/L6 は両 ISA、L5 はリンク済み) ---
# L4 は -O1: -O2 だとベクトル化でループが SIMD 列に置き換わり、
# 「メモリ参照の復元」を測れなくなる。
for case in l0_arith l1_branch l2_loop l6_abi; do
  clang -target aarch64-unknown-linux-gnu -O2 -c "$CASES/c/$case.c" -o "$OUT/${case}_a64.o"
  clang -target x86_64-unknown-linux-gnu  -O2 -c "$CASES/c/$case.c" -o "$OUT/${case}_x64.o"
  built+=("${case}_a64.o" "${case}_x64.o")
done
for isa in aarch64 x86_64; do
  suffix=a64; [ "$isa" = x86_64 ] && suffix=x64
  clang -target "$isa-unknown-linux-gnu" -O1 -c "$CASES/c/l4_memory.c" -o "$OUT/l4_memory_$suffix.o"
  built+=("l4_memory_$suffix.o")
done
if command -v ld.lld >/dev/null 2>&1; then
  clang -target aarch64-unknown-linux-gnu -O2 -c "$CASES/c/l5_switch.c" -o "$OUT/l5_switch.o"
  ld.lld -m aarch64elf -e dense -o "$OUT/l5_switch.elf" "$OUT/l5_switch.o"
  built+=(l5_switch.elf)
fi

# --- Go(名前は pclntab から; Go がある場合のみ) ---
# Go は PATH に無いことがある。GO_BIN、次に一般的な導入先を見る。
if [ -z "${GO_BIN:-}" ]; then
  GO_BIN=$(command -v go || true)
fi
if [ -z "$GO_BIN" ]; then
  for candidate in /usr/local/go/bin/go /opt/homebrew/opt/go/bin/go /usr/lib/go/bin/go; do
    [ -x "$candidate" ] && { GO_BIN=$candidate; break; }
  done
fi
if [ -n "$GO_BIN" ] && [ -x "$GO_BIN" ]; then
  ( cd "$CASES/go" && GO111MODULE=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      "$GO_BIN" build -trimpath -ldflags "-s -w" -o "../../out/go_stripped" add.go )
  ( cd "$CASES/go" && GO111MODULE=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      "$GO_BIN" build -trimpath -ldflags "-s -w" -o "../../out/go_probe" probe.go )
  built+=(go_stripped go_probe)
else
  echo "warn: go not found (set GO_BIN); Go fixtures skipped" >&2
  skipped+=(go)
fi

# --- Rust / C++(デマングリング; ツールチェーンがある場合のみ) ---
RUSTC=${RUSTC:-$(command -v rustc || true)}
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
  echo "warn: rustc not found; Rust fixtures skipped" >&2
  skipped+=(rust)
fi

CXX=${CXX:-$(command -v clang++ || true)}
if [ -n "$CXX" ] && [ -x "$CXX" ]; then
  "$CXX" -O2 -c "$CASES/cpp/namespace.cpp" -o "$OUT/cpp_demo.o"
  built+=(cpp_demo.o)
fi

# --- 大容量入力(ローダ/走査の性能回帰; 20 MB の詰め物) ---
if [ ! -f "$OUT/arm64_big.o" ] || [ "$OUT/arm64.o" -nt "$OUT/arm64_big.o" ]; then
  cat "$OUT/arm64.o" > "$OUT/arm64_big.o"
  dd if=/dev/zero bs=1048576 count=20 >> "$OUT/arm64_big.o" 2>/dev/null
fi

# ladder.sh が「どのフィクスチャが縮退しているか」を知るための印。
printf '%s\n' "${skipped[@]:-}" | sed '/^$/d' > "$OUT/skipped.txt"

echo "fixtures: ${#built[@]} built in $OUT"
if [ ${#skipped[@]} -gt 0 ]; then
  echo "skipped: ${skipped[*]} (対応するケースは ladder で SKIP になる)"
fi
