#!/usr/bin/env bash
# 回帰用フィクスチャ生成(生成物は tests/out/ に置き、コミットしない)
# 必要: clang(Apple clang で COFF/AArch64 ELF を生成可能)、lld-link
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=tests/out
mkdir -p "$OUT/src"

if ! command -v clang >/dev/null 2>&1; then
  echo "skip: clang not found" >&2
  exit 1
fi

# --- PE64 (x86-64, CRT 非依存) ---
cat > "$OUT/src/pe64.c" <<'CEOF'
int reg_add(int a, int b) { return a + b; }
int reg_mul(int a, int b) { return a * b; }
int reg_sign(signed char a, short b) { return a + b; }
int reg_max(int a, int b) { return a > b ? a : b; }
int reg_negative(int x) { return x < 0; }
long reg_abs(long x) { return x < 0 ? -x : x; }
const char *kMsg = "velk-ref-string";
int msg_first(void) { return kMsg[1]; }
int reg_div(int a, int b) { return a / b; }
int reg_mod(int a, int b) { return a % b; }
void entry(void) {
    volatile int x = reg_add(2, 3);
    volatile int y = reg_mul(x, 7);
    (void)y;
}
CEOF
clang --target=x86_64-pc-windows-msvc -ffreestanding -O2 -c \
  "$OUT/src/pe64.c" -o "$OUT/pe64.obj"
if command -v lld-link >/dev/null 2>&1; then
  lld-link /out:"$OUT/pe64.exe" /entry:entry /nodefaultlib /subsystem:console \
    /export:reg_add /export:reg_mul /export:reg_sign /export:reg_max \
    /export:reg_negative /export:reg_abs /export:msg_first /export:reg_div \
    /export:reg_mod "$OUT/pe64.obj"
else
  echo "warn: lld-link not found; PE fixture limited to COFF object" >&2
  cp "$OUT/pe64.obj" "$OUT/pe64.exe"
fi

# --- AArch64 ELF (relocatable; 節重なり解決の回帰) ---
cat > "$OUT/src/arm64.c" <<'CEOF'
int sum3(int a, int b, int c) { return a + b + c; }
int helper(int x) {
    int r = 0;
    for (int i = 0; i < x; i++) r += i * i;
    return r;
}
struct pair { int a; int b; };
int pair_sum(const struct pair *p) { return p->a + p->b; }
int sum_arr(const int *p, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) total += p[i];
    return total;
}
CEOF
clang -target aarch64-unknown-linux-gnu -O2 -c \
  "$OUT/src/arm64.c" -o "$OUT/arm64.o"

# --- AArch64 ELF(定数除算のマジック復元回帰) ---
cat > "$OUT/src/div.c" <<'CEOF'
unsigned udiv3(unsigned x) { return x / 3; }
unsigned udiv10(unsigned x) { return x / 10; }
unsigned udiv64(unsigned x) { return x / 64; }
unsigned long long hdiv3(unsigned long long x) { return x / 3; }
unsigned long long hdiv10(unsigned long long x) { return x / 10; }
int sdiv3(int x) { return x / 3; }
int sdiv10(int x) { return x / 10; }
int sdiv16(int x) { return x / 16; }
long long ldiv16(long long x) { return x / 16; }
int smod3(int x) { return x % 3; }
unsigned umod3(unsigned x) { return x % 3; }
unsigned umod10(unsigned x) { return x % 10; }
int smod10(int x) { return x % 10; }
long long lmod10(long long x) { return x % 10; }
unsigned long long umod10b(unsigned long long x) { return x % 10; }
long long lmod16(long long x) { return x % 16; }
int smod4(int x) { return x % 4; }
int negate(int x) { return -x; }
int is_neg(int x) { return x < 0; }
int is_zero(int x) { return x == 0; }
int is_pos(int x) { return x > 0; }
long lnegate(long x) { return -x; }

long long lmod3(long long x) { return x % 3; }
long long ldiv3(long long x) { return x / 3; }
long long ldiv10(long long x) { return x / 10; }
CEOF
clang -target aarch64-unknown-linux-gnu -O2 -c \
  "$OUT/src/div.c" -o "$OUT/arm64_div.o"

# --- x86-64 Mach-O(符号付き64bitマジックと2べきselectの回帰) ---
cat > "$OUT/src/x64div.c" <<'CEOF'
long long l3(long long x) { return x / 3; }
long long l10(long long x) { return x / 10; }
unsigned long long h3(unsigned long long x) { return x / 3; }
unsigned long long h10(unsigned long long x) { return x / 10; }
unsigned u64(unsigned x) { return x / 3; }
int sdiv16x(int x) { return x / 16; }
long long ldiv16x(long long x) { return x / 16; }
int umod3x(unsigned x) { return x % 3; }
int smod3x(int x) { return x % 3; }
unsigned pmod8x(unsigned x) { return x % 8; }
int pmod8s(int x) { return x % 8; }
long long pmod16l(long long x) { return x % 16; }
long long pdiv16l(long long x) { return x / 16; }
long long lmod10x(long long x) { return x % 10; }
unsigned long long umod10x(unsigned long long x) { return x % 10; }
int pdiv64(int x) { return x / 64; }
long long qdiv64(long long x) { return x / 64; }
int pdiv10(int x) { return x / 10; }
CEOF
clang -arch x86_64 -O2 -c "$OUT/src/x64div.c" -o "$OUT/x64_div.o"

# --- AArch64 ELF(別名の同型関数; シグネチャ同定の回帰) ---
cat > "$OUT/src/alt.c" <<'CEOF'
int alt_sum3(int a, int b, int c) { return a + b + c; }
int alt_helper(int x) {
    int r = 0;
    for (int i = 0; i < x; i++) r += i * i;
    return r;
}
CEOF
clang -target aarch64-unknown-linux-gnu -O2 -c \
  "$OUT/src/alt.c" -o "$OUT/alt.o"

# --- AArch64 ELF(トップテストのループ; while 構造化の回帰) ---
cat > "$OUT/src/loops.c" <<'CEOF'
int count_bits(unsigned x) {
    int n = 0;
    while (x) {
        n += x & 1;
        x >>= 1;
    }
    return n;
}
int sum_until(int limit) {
    int total = 0;
    for (int i = 1; i <= limit; i++) total += i;
    return total;
}
int sum_till_neg(const int *p, int n) {
    int total = 0;
    int i = 0;
    while (i < n) {
        int v = p[i];
        if (v < 0) break;
        total += v;
        i++;
    }
    return total;
}
int sum_until_zero(const int *p, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        if (p[i] == 0) break;
        if (p[i] < 0) continue;
        total += p[i];
    }
    return total;
}
CEOF
clang -target aarch64-unknown-linux-gnu -O2 -c \
  "$OUT/src/loops.c" -o "$OUT/arm64_loops.o"
clang -target aarch64-unknown-linux-gnu -O0 -c \
  "$OUT/src/loops.c" -o "$OUT/arm64_loops0.o"

# --- AArch64 リンク済み ELF(adrp/add 経由の文字列参照; ld.lld がある場合のみ) ---
if command -v ld.lld >/dev/null 2>&1; then
  cat > "$OUT/src/str_a64.c" <<'CEOF'
const char *kName = "velk-aarch64-string";
int pick(void) { return kName[2]; }
CEOF
  clang -target aarch64-unknown-linux-gnu -O2 -c \
    "$OUT/src/str_a64.c" -o "$OUT/str_a64.o"
  ld.lld -m aarch64elf -e pick -o "$OUT/arm64_linked.elf" "$OUT/str_a64.o"
fi

# --- AArch64 リンク済み ELF(値テーブル型 switch; ld.lld がある場合のみ) ---
if command -v ld.lld >/dev/null 2>&1; then
  cat > "$OUT/src/sw.c" <<'CEOF'
int dispatch(int x) {
    switch (x) {
    case 10: return 1;
    case 11: return 3;
    case 12: return 7;
    case 13: return 9;
    case 14: return 11;
    default: return 0;
    }
}
CEOF
  clang -target aarch64-unknown-linux-gnu -O2 -c \
    "$OUT/src/sw.c" -o "$OUT/sw.o"
  ld.lld -m aarch64elf -e dispatch -o "$OUT/arm64_switch.elf" "$OUT/sw.o"
fi

# --- AArch64 リンク済み ELF(間接分岐ジャンプテーブル; ld.lld がある場合のみ) ---
if command -v ld.lld >/dev/null 2>&1; then
  cat > "$OUT/src/jumptable.c" <<'CEOF'
volatile int g;
int d7(int x) {
    switch (x) {
    case 0: for (int j = 0; j < 1; j++) g += j; break;
    case 1: for (int j = 0; j < 2; j++) g += j; break;
    case 2: for (int j = 0; j < 3; j++) g += j; break;
    case 3: for (int j = 0; j < 4; j++) g += j; break;
    case 4: for (int j = 0; j < 5; j++) g += j; break;
    case 5: for (int j = 0; j < 6; j++) g += j; break;
    case 6: for (int j = 0; j < 7; j++) g += j; break;
    case 7: for (int j = 0; j < 8; j++) g += j; break;
    case 8: for (int j = 0; j < 9; j++) g += j; break;
    case 9: for (int j = 0; j < 10; j++) g += j; break;
    default: g = -1; break;
    }
    return g;
}
CEOF
  clang -target aarch64-unknown-linux-gnu -O2 -c \
    "$OUT/src/jumptable.c" -o "$OUT/jumptable.o"
  ld.lld -m aarch64elf -e d7 -o "$OUT/arm64_jumptable.elf" "$OUT/jumptable.o"
fi

# --- Go(pclntab からの関数名復元; Go がある場合のみ) ---
GO_BIN=${GO_BIN:-$(command -v go || true)}
if [ -n "$GO_BIN" ] && [ -x "$GO_BIN" ]; then
  mkdir -p "$OUT/gosrc"
  cat > "$OUT/gosrc/main.go" <<'CEOF'
package main

//go:noinline
func add(a int, b int) int { return a + b }

//go:noinline
func twice(x int) int { return add(x, x) }

func main() { println(twice(21)) }
CEOF
  GO111MODULE=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    "$GO_BIN" build -trimpath -ldflags "-s -w" \
    -o "$OUT/go_stripped" "$OUT/gosrc/main.go"
fi

# --- AArch64 リンク済み ELF(DWARF 名復元; ld.lld がある場合のみ) ---
if command -v ld.lld >/dev/null 2>&1; then
  clang -g -target aarch64-unknown-linux-gnu -O2 -c \
    "$OUT/src/arm64.c" -o "$OUT/arm64_debug.o"
  ld.lld -m aarch64elf -e sum3 -o "$OUT/arm64_debug.elf" "$OUT/arm64_debug.o"
  OBJCOPY=${LLVM_OBJCOPY:-$(command -v llvm-objcopy || true)}
  if [ -z "$OBJCOPY" ] && [ -x /opt/homebrew/opt/llvm/bin/llvm-objcopy ]; then
    OBJCOPY=/opt/homebrew/opt/llvm/bin/llvm-objcopy
  fi
  if [ -n "$OBJCOPY" ]; then
    "$OBJCOPY" --remove-section=.symtab --remove-section=.strtab \
      "$OUT/arm64_debug.elf" "$OUT/arm64_debug_stripped.elf"
    # A stripped relocatable object: no symbols, no entry, only the code.
    STRIP=${LLVM_STRIP:-$(command -v llvm-strip || true)}
    if [ -z "$STRIP" ] && [ -x /opt/homebrew/opt/llvm/bin/llvm-strip ]; then
      STRIP=/opt/homebrew/opt/llvm/bin/llvm-strip
    fi
    if [ -n "$STRIP" ]; then
      "$STRIP" -s "$OUT/arm64_loops.o" -o "$OUT/arm64_loops_stripped.o"
    fi
  fi
fi
# --- x86-64 の strip 済みオブジェクト(関数発見の回帰) ---
if command -v clang >/dev/null 2>&1; then
  STRIP=${LLVM_STRIP:-$(command -v llvm-strip || true)}
  if [ -z "$STRIP" ] && [ -x /opt/homebrew/opt/llvm/bin/llvm-strip ]; then
    STRIP=/opt/homebrew/opt/llvm/bin/llvm-strip
  fi
  if [ -n "$STRIP" ]; then
    clang -target x86_64-unknown-linux-gnu -O2 -c \
      "$OUT/src/loops.c" -o "$OUT/x64_loops.o"
    "$STRIP" -s "$OUT/x64_loops.o" -o "$OUT/x64_loops_stripped.o"
    # A tail call ends a function without a `ret`.
    cat > "$OUT/src/tail.c" <<'CEOF'
__attribute__((noinline)) int tail_one(int x) { volatile int y = x * 3; return y + 1; }
__attribute__((noinline)) int tail_two(int x) { return tail_one(x + 2); }
__attribute__((noinline)) int tail_three(int x) { volatile int z = x - 7; return z; }
CEOF
    clang -target aarch64-unknown-linux-gnu -O2 -c \
      "$OUT/src/tail.c" -o "$OUT/arm64_tail.o" 2>/dev/null || true
    if [ -f "$OUT/arm64_tail.o" ]; then
      "$STRIP" -s "$OUT/arm64_tail.o" -o "$OUT/arm64_tail_stripped.o"
    fi
    # An indirect tail call (`br x2`) ends a function as well.
    cat > "$OUT/src/tailptr.c" <<'CEOF'
typedef int (*hook)(int);
__attribute__((noinline)) int via_ptr(hook f, int x) { return f(x + 1); }
__attribute__((noinline)) int after_ptr(int x) { volatile int y = x + 5; return y; }
CEOF
    clang -target aarch64-unknown-linux-gnu -O2 -c \
      "$OUT/src/tailptr.c" -o "$OUT/arm64_tailptr.o" 2>/dev/null || true
    if [ -f "$OUT/arm64_tailptr.o" ]; then
      "$STRIP" -s "$OUT/arm64_tailptr.o" -o "$OUT/arm64_tailptr_stripped.o"
    fi
  fi
fi

# --- デマングリング(Rust / C++; ツールチェーンがある場合のみ) ---
RUSTC=${RUSTC:-$(command -v rustc || true)}
if [ -n "$RUSTC" ] && [ -x "$RUSTC" ]; then
  cat > "$OUT/src/rust_demo.rs" <<'CEOF'
#[inline(never)]
fn add(a: i32, b: i32) -> i32 { a + b }

#[inline(never)]
fn twice(x: i32) -> i32 { add(x, x) }

fn main() { println!("{}", twice(21)); }
CEOF
  "$RUSTC" -O -o "$OUT/rust_demo" "$OUT/src/rust_demo.rs"
fi

CXX=${CXX:-$(command -v clang++ || true)}
if [ -n "$CXX" ] && [ -x "$CXX" ]; then
  cat > "$OUT/src/cpp_demo.cpp" <<'CEOF'
namespace ns {
__attribute__((noinline)) int add(int a, int b) { return a + b; }
__attribute__((noinline)) int mul(int a, int b) { return a * b; }
}
int use(int x) { return ns::add(x, ns::mul(x, 2)); }
CEOF
  "$CXX" -O2 -c "$OUT/src/cpp_demo.cpp" -o "$OUT/cpp_demo.o"
fi

# --- 大容量入力(ローダ/走査の性能回帰) ---
if [ ! -f "$OUT/arm64_big.o" ] || [ "$OUT/arm64.o" -nt "$OUT/arm64_big.o" ]; then
  cat "$OUT/arm64.o" > "$OUT/arm64_big.o"
  dd if=/dev/zero bs=1048576 count=20 >> "$OUT/arm64_big.o" 2>/dev/null
fi

echo "fixtures: $OUT/pe64.exe $OUT/arm64.o $OUT/arm64_div.o $OUT/alt.o $OUT/arm64_loops.o $OUT/arm64_loops0.o $OUT/arm64_big.o"
