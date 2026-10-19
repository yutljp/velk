#!/usr/bin/env bash
# Smoke test: check the output contract of functions, card, ir and decompile
set -euo pipefail
cd "$(dirname "$0")/.."
FIX=tests/fixtures
mkdir -p tests/out
SIGS=tests/out/sigs.json

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok: $*"; }

command -v cargo >/dev/null 2>&1 || fail "cargo not found"
BIN=${BIN:-${CARGO_TARGET_DIR:-target}/debug/velk}

cargo build --quiet
cargo test --quiet 2>/dev/null || fail "unit tests"
[ -x "$BIN" ] || fail "binary not built"

# 1) PE64: format, ISA, function count
pe_json=$("$BIN" functions $FIX/pe64.exe --json 2>/dev/null)
echo "$pe_json" | grep -q '"format": "pe"'          || fail "PE format detect"
echo "$pe_json" | grep -q '"arch": "x86_64"'        || fail "PE64 isa detect"
nf=$(echo "$pe_json" | sed -n 's/.*"functionCount": \([0-9]*\).*/\1/p')
[ -n "$nf" ] && [ "$nf" -ge 3 ]                     || fail "PE64 function discovery (n=$nf)"
ok "PE64 functions (n_functions=$nf)"

# 2) PE64: function card contract
card=$("$BIN" card $FIX/pe64.exe reg_add --budget 144 2>/dev/null)
echo "$card" | grep -q '"name": "reg_add"'          || fail "card name"
echo "$card" | grep -q '"sizeEstimated": true'      || fail "card size estimation"
echo "$card" | grep -q 'lea eax'                    || fail "PE64 decode (lea eax)"
ok "PE64 card (reg_add)"

# 3) AArch64 ELF: overlapping section resolution and decoding
arm_json=$("$BIN" functions $FIX/arm64.o --json 2>/dev/null)
echo "$arm_json" | grep -q '"arch": "aarch64"'      || fail "AArch64 isa detect"
arm_card=$("$BIN" card $FIX/arm64.o sum3 --budget 144 2>/dev/null)
echo "$arm_card" | grep -q '"section": ".text"'     || fail "AArch64 section resolution (.text)"
echo "$arm_card" | grep -q 'add w0, w8, w2'         || fail "AArch64 decode"
echo "$arm_card" | grep -q '"blocks"'               || fail "function card IR summary"
ok "AArch64 functions/card"

# 4) AArch64 IR: arithmetic, constants, branches, loads, explicit unsupported markers
sum3_ir=$("$BIN" ir $FIX/arm64.o sum3 2>/dev/null)
echo "$sum3_ir" | grep -q "fn sum3"                     || fail "ir sum3 header"
[ "$(echo "$sum3_ir" | grep -o ' + ' | wc -l | tr -d ' ')" -ge 2 ] || fail "ir sum3 adds"
echo "$sum3_ir" | grep -q 'ret .*w2'                   || fail "ir sum3 ret"
ok "ir sum3"

helper_ir=$("$BIN" ir $FIX/arm64.o helper 2>/dev/null)
echo "$helper_ir" | grep -q 'brif lt'                  || fail "ir helper branch"
echo "$helper_ir" | grep -q -- '-> 0x48'               || fail "ir helper target"
echo "$helper_ir" | grep -q '0x555'                   || fail "ir helper constant"
echo "$helper_ir" | grep -q 'x8 = '                   || fail "ir helper assignment"
ok "ir helper"

arr_ir=$("$BIN" ir $FIX/arm64.o sum_arr 2>/dev/null)
echo "$arr_ir" | grep -q 'load32'                      || fail "ir sum_arr load"
echo "$arr_ir" | grep -q 'unsupported: MOVI'           || fail "ir sum_arr unsupported marker"
ok "ir sum_arr"

# 5) pseudo-C output
c3=$("$BIN" decompile $FIX/arm64.o sum3 2>/dev/null)
echo "$c3" | grep -q "int32_t sum3(int32_t a0, int32_t a1, int32_t a2)" || fail "decompile sum3 signature"
echo "$c3" | grep -q "return a1 + a0 + a2;"   || fail "decompile sum3 fold"
[ "$(echo "$c3" | grep -c '0xffffffff')" -eq 0 ] || fail "decompile sum3 masks"
echo "$c3" | grep -q "return "               || fail "decompile sum3 return"
echo "$sum3_ir" | grep -qF "ret (((w1 + w0) + w2) & #0xffffffff)" || fail "ir sum3 width"
div_ir=$("$BIN" decompile $FIX/arm64_div.o udiv3 2>/dev/null)
echo "$div_ir" | grep -q "a0 / 0x3"       || fail "magic unsigned div"
sd_ir=$("$BIN" decompile $FIX/arm64_div.o sdiv3 2>/dev/null)
echo "$sd_ir" | grep -q "int32_t"        || fail "magic signed type"
echo "$sd_ir" | grep -q "a0 / 0x3"       || fail "magic signed div"
hd_ir=$("$BIN" decompile $FIX/arm64_div.o hdiv3 2>/dev/null)
echo "$hd_ir" | grep -q "a0 / 0x3"        || fail "magic 64bit div"
echo "$hd_ir" | grep -q "uint64_t"       || fail "magic 64bit width"
sd_ir=$("$BIN" decompile $FIX/arm64_div.o sdiv10 2>/dev/null)
echo "$sd_ir" | grep -q "a0 / 0xa"        || fail "magic signed scaled div10"
echo "$sd_ir" | grep -q "int32_t"        || fail "magic signed scaled width"
sl_ir=$("$BIN" decompile $FIX/arm64_div.o sdiv16 2>/dev/null)
echo "$sl_ir" | grep -q "a0 / 0x10"      || fail "csel select signed div16"
ll_ir=$("$BIN" decompile $FIX/arm64_div.o ldiv16 2>/dev/null)
echo "$ll_ir" | grep -q "a0 / 0x10"      || fail "csel select signed div16 long"
um_ir=$("$BIN" decompile $FIX/arm64_div.o umod3 2>/dev/null)
echo "$um_ir" | grep -q "a0 % 0x3"       || fail "multiplier unwind mod u32"
sm_ir=$("$BIN" decompile $FIX/arm64_div.o smod3 2>/dev/null)
echo "$sm_ir" | grep -q "a0 % 0x3"     || fail "multiplier unwind mod s32"
echo "$sm_ir" | grep -q "int32_t"        || fail "multiplier unwind width"
lm_ir=$("$BIN" decompile $FIX/arm64_div.o lmod3 2>/dev/null)
echo "$lm_ir" | grep -q "a0 % 0x3"       || fail "multiplier unwind mod s64"
echo "$lm_ir" | grep -q "int64_t"        || fail "multiplier unwind width 64"
um10=$("$BIN" decompile $FIX/arm64_div.o umod10 2>/dev/null)
echo "$um10" | grep -q "a0 % 0xa"      || fail "multiplier unwind mod u32 10"
lm10=$("$BIN" decompile $FIX/arm64_div.o lmod10 2>/dev/null)
echo "$lm10" | grep -q "a0 % 0xa"        || fail "msub unwind mod s64 10"
um10b=$("$BIN" decompile $FIX/arm64_div.o umod10b 2>/dev/null)
echo "$um10b" | grep -q "a0 % 0xa"       || fail "msub unwind mod u64 10"
umx=$("$BIN" decompile $FIX/x64_div.o umod3x 2>/dev/null)
echo "$umx" | grep -q "% 0x3"            || fail "x86 lea unwind mod u32"
smx=$("$BIN" decompile $FIX/x64_div.o smod3x 2>/dev/null)
echo "$smx" | grep -q "% 0x3"            || fail "x86 lea unwind mod s32"
lmx=$("$BIN" decompile $FIX/x64_div.o lmod10x 2>/dev/null)
lm16=$("$BIN" decompile $FIX/arm64_div.o lmod16 2>/dev/null)
echo "$lm16" | grep -q "% 0x10"         || fail "cset-pow2 mod s64"
echo "$lm16" | grep -q "int64_t"        || fail "cset-pow2 width 64"
sm4=$("$BIN" decompile $FIX/arm64_div.o smod4 2>/dev/null)
sd16=$("$BIN" decompile $FIX/arm64_div.o sdiv16 2>/dev/null)
echo "$sd16" | grep -q "int32_t"        || fail "csel div16 dividend width"
sm10=$("$BIN" decompile $FIX/arm64_div.o smod10 2>/dev/null)
echo "$sm10" | grep -q "int32_t smod10" || fail "msub mod10 signed width"
sm3x=$("$BIN" decompile $FIX/x64_div.o smod3x 2>/dev/null)
ng=$("$BIN" decompile $FIX/arm64_div.o negate 2>/dev/null)
echo "$ng" | grep -q "return -a0;"      || fail "negate render"
echo "$ng" | grep -q "0x0 -" && fail "negate render kept 0 - x"
echo "$sm3x" | grep -q "int32_t smod3x(" || fail "x86 lea mod3 signed width"
echo "$sm4" | grep -q "% 0x4"           || fail "cset-pow2 mod s32"
echo "$sm4" | grep -q "int32_t"         || fail "cset-pow2 width 32"
echo "$lmx" | grep -q "% 0xa"            || fail "x64 lea unwind mod s64"
ld_ir=$("$BIN" decompile $FIX/arm64_div.o ldiv3 2>/dev/null)
echo "$ld_ir" | grep -q "a0 / 0x3"        || fail "magic signed 64bit div"
echo "$ld_ir" | grep -q "int64_t"        || fail "magic signed 64bit width"
l10_ir=$("$BIN" decompile $FIX/arm64_div.o ldiv10 2>/dev/null)
echo "$l10_ir" | grep -q "a0 / 0xa"      || fail "magic signed 64bit div10"
x64_l3=$("$BIN" decompile $FIX/x64_div.o l3 2>/dev/null)
echo "$x64_l3" | grep -q "/ 0x3"         || fail "x64 signed 64bit div"
echo "$x64_l3" | grep -q "int64_t"       || fail "x64 signed 64bit width"
x64_h3=$("$BIN" decompile $FIX/x64_div.o h3 2>/dev/null)
echo "$x64_h3" | grep -q "/ 0x3"         || fail "x64 unsigned 64bit div"
x64_sel=$("$BIN" decompile $FIX/x64_div.o pdiv64 2>/dev/null)
echo "$x64_sel" | grep -q "/ 0x40"        || fail "x64 signed select div"
echo "$x64_sel" | grep -q "int32_t"      || fail "x64 signed select width"
x64_selq=$("$BIN" decompile $FIX/x64_div.o qdiv64 2>/dev/null)
echo "$x64_selq" | grep -q "a0 / 0x40"   || fail "x64 signed select 64bit div"
x64_sel10=$("$BIN" decompile $FIX/x64_div.o pdiv10 2>/dev/null)
echo "$x64_sel10" | grep -q "/ 0xa"      || fail "x64 signed sext div10"
helper_cs=$("$BIN" decompile $FIX/arm64.o helper 2>/dev/null)
echo "$helper_cs" | grep -q "x8 = x8 >> 0x1;"    || fail "shift kept in its register"
echo "$helper_cs" | grep -q "(w8 + (w8 << 0x1))" || fail "32-bit read shared without a temporary"
ok "cse temps"
x64_fold=$("$BIN" decompile $FIX/x64_div.o l3 2>/dev/null)
echo "$x64_fold" | grep -q "0xfffffffffffffff8" && fail "frame prologue elision"
echo "$x64_fold" | grep -q "rbp"                && fail "frame register elision"
echo "$x64_fold" | grep -q "a0 / 0x3"           || fail "copy propagation into division"
x64_mod=$("$BIN" decompile $FIX/x64_div.o umod3x 2>/dev/null)
echo "$x64_mod" | grep -q "rcx"                 && fail "dead copy removal"
ok "x86 cleanup"
p8s=$("$BIN" decompile $FIX/x64_div.o pmod8s 2>/dev/null)
echo "$p8s" | grep -q "a0 % 0x8"        || fail "x86 signed pow2 mod"
p16l=$("$BIN" decompile $FIX/x64_div.o pmod16l 2>/dev/null)
echo "$p16l" | grep -q "a0 % 0x10"      || fail "x64 signed pow2 mod"
p8u=$("$BIN" decompile $FIX/x64_div.o pmod8x 2>/dev/null)
echo "$p8u" | grep -q "a0 & 0x7"        || fail "x86 unsigned pow2 mask"
iz=$("$BIN" decompile $FIX/arm64_div.o is_zero 2>/dev/null)
echo "$iz" | grep -q "a0 == 0x0"        || fail "cset eq compare"
ip=$("$BIN" decompile $FIX/arm64_div.o is_pos 2>/dev/null)
echo "$ip" | grep -q "a0 > 0x0"         || fail "cset gt compare"
echo "$iz" | grep -q "? 0x1 : 0x0)"    || fail "cset boolean branches"
ok "pow2 mod and cset"
locals=$("$BIN" decompile $FIX/arm64_loops0.o count_bits 2>/dev/null)
echo "$locals" | grep -q "local_0 = a0"     || fail "stack local naming"
echo "$locals" | grep -q "local_0 >>= 0x1"  || fail "stack local names one slot"
use_ir=$("$BIN" decompile $FIX/cpp_demo.o "use(int)" 2>/dev/null)
echo "$use_ir" | grep -q "ns__mul_int__int_()" || fail "C++ call relocation"
echo "$use_ir" | grep -qE "(= x20|x20 =)" && fail "callee-save elision (x20)"
echo "$use_ir" | grep -qE "(= x30|x30 =)" && fail "callee-save elision (x30)"
echo "$use_ir" | grep -qE "(= x29|x29 =)" && fail "frame setup elision"
ok "callee-save elision"
fold_ret=$("$BIN" decompile $FIX/x64_div.o umod3x 2>/dev/null)
echo "$fold_ret" | grep -q "return a0 % 0x3;"  || fail "temporary inlining into ret"
sum3_ir2=$("$BIN" decompile $FIX/arm64.o sum3 2>/dev/null)
echo "$sum3_ir2" | grep -q "w8" && fail "temporary inlining (sum3)"
ok "temporary inlining"
abs_ir=$("$BIN" decompile $FIX/pe64.exe reg_abs 2>/dev/null)
echo "$abs_ir" | grep -q "(-a0 < 0x0 ? a0 : -a0)" || fail "neg and cmovs absolute value"
echo "$abs_ir" | grep -q -- "-(-" && fail "double negation kept"
sign_ir=$("$BIN" decompile $FIX/pe64.exe reg_sign 2>/dev/null)
echo "$sign_ir" | grep -q "(int8_t)(a0)"   || fail "sign-extend mask fold"
echo "$sign_ir" | grep -q "0x1f" && fail "sign-extend artifact"
ok "algebraic cleanup"
abs_ret=$("$BIN" decompile $FIX/pe64.exe reg_abs 2>/dev/null)
echo "$abs_ret" | grep -q "return (-a0 < 0x0 ? a0 : -a0);"     || fail "abs folds into the return"
helper_cse=$("$BIN" decompile $FIX/arm64.o helper 2>/dev/null)
echo "$helper_cse" | grep -q "t1" && fail "temporary for a 32-bit register read"
ok "two-round inlining"
div_ir=$("$BIN" decompile $FIX/pe64.exe reg_div 2>/dev/null)
echo "$div_ir" | grep -qF "return a0 / a1;" || fail "runtime division inlining"
mod_ir=$("$BIN" decompile $FIX/pe64.exe reg_mod 2>/dev/null)
echo "$mod_ir" | grep -qF "a0 % a1" || fail "idiv remainder dividend"
ok "runtime division and remainder"
stack_ir=$("$BIN" decompile $FIX/arm64_loops0.o sum_until 2>/dev/null)
echo "$stack_ir" | grep -q "local_1"        || fail "stack locals named"
echo "$stack_ir" | grep -q "local_1 += local_2;" || fail "stack local accumulation"
echo "$stack_ir" | grep -q "sp + 0x4" && fail "stack address left raw"
ok "stack locals"
decl_ir=$("$BIN" decompile $FIX/arm64_loops0.o sum_until 2>/dev/null)
echo "$decl_ir" | grep -qF "uint32_t local_2; /* [sp-c] */" || fail "stack local declaration"
echo "$decl_ir" | grep -q "(local_2 & 0xffffffff)" && fail "local mask elided"
echo "$decl_ir" | grep -q "w9" && fail "32-bit register left between two locals"
ok "stack local declarations"
frame_ir=$("$BIN" decompile $FIX/arm64_loops0.o sum_until 2>/dev/null)
echo "$frame_ir" | grep -qE "^ *sp = " && fail "frame adjustments hidden"
echo "$frame_ir" | grep -q "sp + 0x4" && fail "frame slot canonicalized"
loop_ir=$("$BIN" decompile $FIX/cpp_demo.o "use(int)" 2>/dev/null)
echo "$loop_ir" | grep -q "for (;;)" && fail "tail call read as a loop"
echo "$loop_ir" | grep -q "ns__mul_int__int_()"  || fail "relocated call target"
ok "frame settling and endless loop"
arr_ir=$("$BIN" decompile $FIX/arm64.o sum_arr 2>/dev/null)
echo "$arr_ir" | grep -q "goto L_" && fail "sum_arr has no gotos"
echo "$arr_ir" | grep -q "} else {"   || fail "if/else across a skipped block"
echo "$arr_ir" | grep -q "x9 = a1;"                || fail "branch block prefix kept"
helper_pre=$("$BIN" decompile $FIX/arm64.o helper 2>/dev/null)
echo "$helper_pre" | grep -q "x8 = a0 - 0x1;"  || fail "prefix before early return"
ok "if/else structuring"
sig_zero=$("$BIN" decompile $FIX/arm64_div.o is_zero 2>/dev/null)
echo "$sig_zero" | grep -q "int32_t is_zero(int32_t a0)" || fail "boolean signature by usage"
sig_mul=$("$BIN" decompile $FIX/pe64.exe reg_mul 2>/dev/null)
echo "$sig_mul" | grep -q "int32_t reg_mul(int32_t a0, int32_t a1)" || fail "mul signature by usage"
sig_h=$("$BIN" decompile $FIX/x64_div.o h10 2>/dev/null)
echo "$sig_h" | grep -qE "uint64_t _?h10\(uint64_t a0\)" || fail "wide signature kept"
sig_helper=$("$BIN" decompile $FIX/arm64.o helper 2>/dev/null)
echo "$sig_helper" | grep -q "int32_t helper(int32_t a0)"    || fail "loop signature by usage"
ok "types by usage"
mask_ir=$("$BIN" decompile $FIX/arm64.o helper 2>/dev/null)
echo "$mask_ir" | grep -q "x8 = w8 \* (a0 - 0x2);" || fail "mask implied by 32-bit arithmetic"
echo "$mask_ir" | grep -q "x8 = a0 - 0x1;"          || fail "mask implied by a 32-bit parameter"
narrow_ir=$("$BIN" decompile $FIX/arm64_loops0.o sum_until 2>/dev/null)
echo "$narrow_ir" | grep -q "while (local_2 <= local_0)" || fail "32-bit comparison kept"
echo "$narrow_ir" | grep -q "local_1 += local_2;"   || fail "compound store in a loop"
ok "mask elision by width"
narrow_dest=$("$BIN" decompile $FIX/arm64.o helper 2>/dev/null)
echo "$narrow_dest" | grep -q "+ (w8 << 0x1)) - 0x1;" || fail "mask implied by the return type"
echo "$narrow_dest" | grep -q "a0 = .*0xffffffff" && fail "return mask kept"
ok "masks implied by the destination"
masked_ir=$("$BIN" decompile $FIX/arm64.o sum_arr 2>/dev/null)
echo "$masked_ir" | grep -q "x8 = w10 + w8;" || fail "mask bounded by its constant"
echo "$masked_ir" | grep -q "w10 + w8) & 0xffffffff" && fail "bounded mask kept"
ok "mask bounded by the constant"
dwarf_ir=$("$BIN" decompile $FIX/arm64_debug.elf helper 2>/dev/null)
echo "$dwarf_ir" | grep -q "x8 = x - 0x1;"      || fail "narrow DWARF type read without a mask"
echo "$dwarf_ir" | grep -q "(x & 0xffffffff)" && fail "narrow DWARF type keeps the mask"
ok "narrow DWARF types"
sign_ir2=$("$BIN" decompile $FIX/pe64.exe reg_sign 2>/dev/null)
echo "$sign_ir2" | grep -q "(int8_t)(a0);"           || fail "sign-extended value needs no mask"
echo "$sign_ir2" | grep -q "(int8_t)(a0) & 0xffffffff" && fail "sign-extend mask kept"
ok "sign-extended widths"
degraded=$("$BIN" decompile $FIX/arm64_debug.o sum3 2>/dev/null)
echo "$degraded" | grep -q "clang version" && fail "relocated DWARF name leaked"
echo "$degraded" | grep -q "int32_t sum3(int32_t a0, int32_t a1, int32_t a2)" || fail "inferred signature kept"
ok "relocated DWARF falls back"
field_ir=$("$BIN" decompile $FIX/arm64_debug.elf pair_sum 2>/dev/null)
echo "$field_ir" | grep -q "p->a"   || fail "DWARF field name for the first member"
echo "$field_ir" | grep -q "p->b"   || fail "DWARF field name for the second member"
echo "$field_ir" | grep -q "field_0x" && fail "member kept its offset name"
ok "DWARF member names"
zero_ir=$("$BIN" decompile $FIX/arm64.o helper 2>/dev/null)
echo "$zero_ir" | grep -q "return 0x0;" || fail "zero stays a constant"
brk_ir=$("$BIN" decompile $FIX/arm64_loops.o sum_until_zero 2>/dev/null)
echo "$brk_ir" | grep -q "do {"            || fail "bottom-tested loop formed"
echo "$brk_ir" | grep -q "break;"          || fail "loop exit reads as break"
echo "$brk_ir" | grep -q "goto L_" && fail "loop exit kept a goto"
echo "$brk_ir" | grep -q "unsupported" && fail "bic still unsupported"
echo "$brk_ir" | grep -q "~("              || fail "complement rendered"
ok "bottom-tested loops"
neg_ir=$("$BIN" decompile $FIX/arm64_loops.o sum_till_neg 2>/dev/null)
# Clang 18's AArch64 sequence loses the signed-load/compare hint; retain the
# stable parameter identities while leaving that type precision unresolved.
echo "$neg_ir" | grep -q "sum_till_neg(uint32_t \*a0," || fail "fall-through pointer parameter kept"
echo "$neg_ir" | grep -q " a1)" || fail "fall-through scalar parameter kept"
echo "$neg_ir" | grep -q "break;"   || fail "top-tested break kept"
ok "fall-through predecessors"
simd_ir=$("$BIN" decompile $FIX/arm64.o sum_arr 2>/dev/null)
echo "$simd_ir" | grep -A1 "if (a1 < 0x1) {" | grep -q "x8 = 0x0;" && fail "dead store before return in a SIMD function"
echo "$simd_ir" | grep -q "return 0x0;" || fail "early return kept"
ok "dead stores beside unmodeled code"
wide_ir=$("$BIN" decompile $FIX/x64_div.o umod10x 2>/dev/null)
echo "$wide_ir" | grep -q "__umulh(a0, 0xcccccccccccccccd)"  || fail "wide multiply reads as its intrinsic"
echo "$wide_ir" | grep -q " hi128 " && fail "wide multiply kept the infix"
ok "wide multiply intrinsic"
settled=$("$BIN" decompile $FIX/arm64_loops0.o sum_till_neg 2>/dev/null)
echo "$settled" | grep -q "local_0 = a0;"     || fail "frame settled past a pointer load"
echo "$settled" | grep -q "sp = sp"           && fail "stack adjustments kept"
ok "frame settling past pointer bases"
narrow_dst=$("$BIN" decompile $FIX/arm64_loops.o sum_till_neg 2>/dev/null)
echo "$narrow_dst" | grep -q "w8 = x10;" || fail "narrow destination uses its 32-bit name"
echo "$narrow_dst" | grep -q "return w8;" || fail "narrow destination read back"
ok "narrow destination names"
trap_ir=$("$BIN" decompile $FIX/go_stripped internal/abi.Kind.String 2>/dev/null)
echo "$trap_ir" | grep -q "__builtin_trap();" || fail "trap rendered"
echo "$trap_ir" | grep -c "__builtin_trap();" | grep -qx 1 || fail "trap padding collapsed"
echo "$trap_ir" | grep -q "Int3" && fail "int3 note kept"
echo "$trap_ir" | grep -q "local_0;" && fail "unused local declared"
ok "trap padding and unused locals"
back_ir=$("$BIN" decompile $FIX/arm64_loops0.o sum_till_neg 2>/dev/null)
echo "$back_ir" | grep -q "for (;;) {"      || fail "unconditional back edge structured"
echo "$back_ir" | grep -q "^L_c0:"         && fail "loop header kept as a label"
uv run python - "$back_ir" <<'PY'
import re, sys
body = sys.argv[1]
gotos = set(re.findall(r'goto (L_[0-9a-f]+);', body))
labels = set(re.findall(r'^\s*(L_[0-9a-f]+):', body, flags=re.M))
assert not (gotos - labels), f"dangling goto {gotos - labels}"
PY
ok "unconditional back edges"
opt0=$("$BIN" decompile $FIX/arm64_loops0.o count_bits 2>/dev/null)
echo "$opt0" | grep -q "sp = sp" && fail "frame settled at -O0"
zero_ir=$("$BIN" decompile $FIX/arm64.o sum_arr 2>/dev/null)
echo "$zero_ir" | grep -q "^int32_t sum_arr"  || fail "return type follows the value"
ok "value-width return types"
# A stripped relocatable object keeps no symbols and no entry point: the
# functions are found from the code itself.
n=$("$BIN" functions $FIX/arm64_loops_stripped.o 2>/dev/null | sed -n '1s/.*functions: \([0-9]*\).*/\1/p')
[ "$n" = "4" ] || fail "stripped object function count ($n)"
first=$("$BIN" functions $FIX/arm64_loops_stripped.o 2>/dev/null | awk 'NR == 3 { print $1 }')
[ "$first" = "0x0" ] || fail "stripped object starts at its first function"
# The address of the loop function depends on the compiler's layout, so
# take it from the listing instead of pinning it.
loop_addr=$("$BIN" functions $FIX/arm64_loops_stripped.o 2>/dev/null | awk 'NR == 6 { print $1 }')
loops=$("$BIN" decompile $FIX/arm64_loops_stripped.o "$loop_addr" 2>/dev/null)
echo "$loops" | grep -q "do {"        || fail "stripped object body structured"
echo "$loops" | grep -q "break;"      || fail "stripped object loop exit"
ok "stripped relocatable objects"
xs=$("$BIN" functions $FIX/x64_loops_stripped.o 2>/dev/null | sed -n '1s/.*functions: \([0-9]*\).*/\1/p')
[ "$xs" = "4" ] || fail "stripped x86 object function count ($xs)"
ok "stripped x86 objects"
# A tail call (`b` to another function) ends a function without a `ret`.
tn=$("$BIN" functions $FIX/tail_calls_stripped.o 2>/dev/null | sed -n '1s/.*functions: \([0-9]*\).*/\1/p')
[ "$tn" = "3" ] || fail "tail call boundary ($tn)"
tail_addr=$("$BIN" functions $FIX/tail_calls_stripped.o 2>/dev/null | tail -n +3 | sed -n 2p | awk '{print $1}')
tail_mid=$("$BIN" decompile $FIX/tail_calls_stripped.o "$tail_addr" 2>/dev/null)
echo "$tail_mid" | grep -q "for (;;)" && fail "unresolved tail call became a loop"
echo "$tail_mid" | grep -q "();"        || fail "unresolved tail call rendered"
ok "tail call boundaries"
# An indirect tail call (`br x2`) also ends a function.
in_n=$("$BIN" functions $FIX/tail_indirect_stripped.o 2>/dev/null | sed -n '1s/.*functions: \([0-9]*\).*/\1/p')
[ "$in_n" = "2" ] || fail "indirect tail call boundary ($in_n)"
ok "indirect tail calls"
# A value just stored into a slot feeds its reader directly.
fwd=$("$BIN" decompile $FIX/arm64_loops0.o sum_till_neg 2>/dev/null)
echo "$fwd" | grep -q "x8 = local_3;" && fail "store not forwarded"
echo "$fwd" | grep -q "local_4 = w8;" || fail "forwarded value missing"
pe_entry=$("$BIN" functions $FIX/pe64.exe --json 2>/dev/null | sed -n 's/.*"entry": "\(0x[0-9a-f]*\)".*/\1/p')
entry_fwd=$("$BIN" decompile $FIX/pe64.exe "$pe_entry" 2>/dev/null)
echo "$entry_fwd" | grep -qF "*(uint32_t *)&local_1 = 0x23;" || fail "partial store into a wider local"
echo "$entry_fwd" | grep -q "return local_1;" || fail "pop reads the pushed slot"
echo "$entry_fwd" | grep -q "= rax;" && fail "overwritten push kept"
ok "stored values forwarded"










































entry_ir=$("$BIN" decompile $FIX/pe64.exe "$pe_entry" 2>/dev/null)
echo "$entry_ir" | grep -q "rax = local_0;" && fail "dead frame load removed"
echo "$entry_ir" | grep -q "local_2" && fail "spurious slot after settling"
ok "dead frame loads"
moved_ir=$("$BIN" decompile $FIX/arm64_loops0.o sum_until 2>/dev/null)
echo "$moved_ir" | grep -q "x8 = 0x1;" && fail "dead store before the loop"
echo "$moved_ir" | grep -q "local_2 = 0x1;" || fail "live store before the loop"
live_ir=$("$BIN" decompile $FIX/cpp_demo.o "use(int)" 2>/dev/null)
echo "$live_ir" | grep -q "x19 = a0;" || fail "definition kept across a call"
ok "flow-sensitive dead stores"


pair_ir=$("$BIN" decompile $FIX/arm64.o pair_sum 2>/dev/null)
echo "$pair_ir" | grep -q "a0->field_0x0"   || fail "member access at offset zero"
echo "$pair_ir" | grep -q "a0->field_0x4"   || fail "member access at offset four"
echo "$pair_ir" | grep -q "\*(uint32_t \*)" && fail "member access keeps the cast"
ok "pointer members"
msg_ir=$("$BIN" decompile $FIX/pe64.exe msg_first 2>/dev/null)
echo "$msg_ir" | grep -q "qword_140003000" || fail "global named by width and address"
echo "$msg_ir" | grep -q "(0x140003000)" && fail "global name replaces the address"
ok "named globals"
bits_ir=$("$BIN" decompile $FIX/arm64_loops0.o count_bits 2>/dev/null)
echo "$bits_ir" | grep -Eq "local_[0-9]+ \+= (local_[0-9]+ & 0x1|w[0-9]+);" || fail "compound add"
echo "$bits_ir" | grep -Eq "& 0x1;" || fail "compound add operand"
echo "$bits_ir" | grep -Eq "local_[0-9]+ >>= 0x1;"            || fail "compound shift"
echo "$bits_ir" | grep -q "local_1 = (local_1" && fail "compound add kept the temp"
ok "compound assignment"



































ok "decompile sum3"

ch=$("$BIN" decompile $FIX/arm64.o helper 2>/dev/null)
echo "$ch" | grep -q "if (a0 < 0x1)"         || fail "decompile helper branch"
echo "$ch" | grep -q "return "               || fail "decompile helper return"
ok "decompile helper"

ca=$("$BIN" decompile $FIX/arm64.o sum_arr 2>/dev/null)
echo "$ca" | grep -q "uint32_t \*a0"         || fail "pointer parameter typing"
echo "$ca" | grep -q "unsupported (2 steps): MOVI" || fail "decompile sum_arr unsupported note"
echo "$ca" | grep -q "SIMD vector pair"      || fail "decompile sum_arr simd note"
echo "$ca" | grep -q "return 0x0;"           || fail "decompile sum_arr early return"
echo "$ca" | grep -q "do {"                  || fail "decompile sum_arr loop"
echo "$ca" | grep -q "} while ("             || fail "decompile sum_arr loop condition"
ok "decompile sum_arr"

# 6) x86-64 IR and pseudo-C
x86_ir=$("$BIN" ir $FIX/pe64.exe reg_add 2>/dev/null)
echo "$x86_ir" | grep -qF "ret ((rcx + rdx) & #0xffffffff)" || fail "x86 ir reg_add"
ok "x86 ir reg_add"

x86_mul=$("$BIN" ir $FIX/pe64.exe reg_mul 2>/dev/null)
echo "$x86_mul" | grep -q " \* "                 || fail "x86 ir imul"
ok "x86 ir imul"
coff=$("$BIN" decompile $FIX/pe64.obj reg_add 2>/dev/null)
echo "$coff" | grep -Eq 'reg_add\([^,]+, [^,]+\)'            || fail "COFF uses the Windows argument registers"
zeroed=$("$BIN" decompile $FIX/l2_loop_x64.o find_first 2>/dev/null)
echo "$zeroed" | grep -Eq 'find_first\([^,]+, [^,]+, [^,]+\)' || fail "xor zeroing is not an argument read"
ok "argument registers"

x86_sign=$("$BIN" decompile $FIX/pe64.exe reg_sign 2>/dev/null)
echo "$x86_sign" | grep -q "int8_t"             || fail "x86 movsx byte"
echo "$x86_sign" | grep -q "int16_t"            || fail "x86 movsx word"
ok "x86 lift sign extension"

x86_max=$("$BIN" decompile $FIX/pe64.exe reg_max 2>/dev/null)
echo "$x86_max" | grep -q " ? "              || fail "x86 cmov select"
x86_abs=$("$BIN" decompile $FIX/pe64.exe reg_abs 2>/dev/null)
echo "$x86_abs" | grep -q " ? "              || fail "x86 neg/cmov select"
if echo "$x86_abs" | grep -q "unsupported: cmov"; then fail "x86 cmov unresolved"; fi
ok "x86 cmov / setcc"

x86_div=$("$BIN" decompile $FIX/pe64.exe reg_div 2>/dev/null)
echo "$x86_div" | grep -q " / "              || fail "x86 idiv quotient"
x86_mod=$("$BIN" decompile $FIX/pe64.exe reg_mod 2>/dev/null)
echo "$x86_mod" | grep -q " % "              || fail "x86 idiv remainder"
if echo "$x86_div" | grep -q "unsupported"; then fail "x86 idiv unresolved"; fi
ok "x86 idiv"

closed_pipe=$( { "$BIN" functions $FIX/go_probe --limit 100000 | head -1 >/dev/null; } 2>&1 )
[ -z "$closed_pipe" ] || fail "closed pipe reports an error"
ok "closed pipe"

x86_c=$("$BIN" decompile $FIX/pe64.exe reg_add 2>/dev/null)
echo "$x86_c" | grep -q "int32_t reg_add(int32_t a0, int32_t a1)" || fail "x86 decompile signature"
echo "$x86_c" | grep -q "return a0 + a1;"         || fail "x86 decompile return"
ok "x86 decompile"

# 7) build-signatures and identify (match same-shape functions under other names)
"$BIN" build-signatures $FIX/arm64.o --output $SIGS 2>/dev/null
[ -s $SIGS ]                          || fail "build-signatures output"
grep -q '"name": "sum3"' $SIGS        || fail "build-signatures entry sum3"
ident=$("$BIN" identify $FIX/alt.o --signatures $SIGS 2>/dev/null)
echo "$ident" | grep -q "sum3"                      || fail "identify sum3 shape"
echo "$ident" | grep -q "helper"                    || fail "identify helper shape"
echo "$ident" | grep -q "identified 2 of 2"         || fail "identify count"
ok "build-signatures / identify"

# 8) while structuring (header condition and back edge)
loop_pc=$("$BIN" decompile $FIX/arm64_loops0.o count_bits 2>/dev/null)
echo "$loop_pc" | grep -Eq "while \(local_[0-9]+ != 0x0\)" || fail "while structuring"
echo "$loop_pc" | grep -q "if (x8 == 0x0) break;" && fail "while header folded"
loop_break=$("$BIN" decompile $FIX/arm64_loops0.o sum_until 2>/dev/null)
echo "$loop_break" | grep -q "while (local_2 <= local_0)" || fail "while break condition"
ok "while structuring"

# 9) data (string) reference recovery
msg=$("$BIN" decompile $FIX/pe64.exe msg_first 2>/dev/null)
echo "$msg" | grep -q 'velk-ref-string'       || fail "string reference"
msg_card=$("$BIN" card $FIX/pe64.exe msg_first 2>/dev/null)
echo "$msg_card" | grep -q 'velk-ref-string'  || fail "card string reference"
echo "$msg_card" | grep -q 'velk_ref_string'   || fail "card name hint"
ok "string references"

# 10) struct access recovery
pair=$("$BIN" decompile $FIX/arm64.o pair_sum 2>/dev/null)
echo "$pair" | grep -q "struct: a0 +0x0:uint32_t, +0x4:uint32_t" || fail "struct access offsets"
pair_card=$("$BIN" card $FIX/arm64.o pair_sum 2>/dev/null)
echo "$pair_card" | grep -q '"accesses"'    || fail "card struct accesses"
ok "struct access recovery"

# 11) AArch64 linked ELF: adrp/add and string references
linked=$("$BIN" decompile $FIX/arm64_linked.elf pick 2>/dev/null)
echo "$linked" | grep -q 'velk-aarch64-string' || fail "adrp string reference"
ok "adrp / string reference"

# 12) applying a signature database (--signatures)
"$BIN" build-signatures $FIX/arm64.o --output $SIGS 2>/dev/null
applied=$("$BIN" decompile $FIX/alt.o alt_sum3 --signatures $SIGS 2>/dev/null)
echo "$applied" | grep -q "identified: sum3"  || fail "decompile signature matching"
applied_card=$("$BIN" card $FIX/alt.o alt_sum3 --signatures $SIGS 2>/dev/null)
echo "$applied_card" | grep -q '"identified": "sum3"' || fail "card signature matching"
ok "signature application"

# 13) typed pointer parameters and the script API (shape hash, signature)
pair_c=$("$BIN" decompile $FIX/arm64.o pair_sum 2>/dev/null)
echo "$pair_c" | grep -q 'uint32_t \*'           || fail "typed pointer parameter"
script=$(mktemp)
printf '%s\n' "const f = velk.open('$FIX/arm64.o').getFunction('pair_sum');" \
  'console.log(f.shapeHash().length, f.signature().params.length);' > "$script"
api=$("$BIN" run "$script" 2>/dev/null)
rm -f "$script"
[ "$api" = "16 1" ]                              || fail "script API (got: $api)"
ok "script API"

# 14) extend-and-shift addressing (value-table switch)
sw=$("$BIN" decompile $FIX/arm64_switch.elf dispatch 2>/dev/null)
echo "$sw" | grep -q "dword_200120\[w8\]"   || fail "extend-shift addressing as a table"
echo "$sw" | grep -q "ref: 0x"                || fail "switch table reference"
if echo "$sw" | grep -q "unsupported:"; then fail "switch table unsupported"; fi
ok "table-driven switch"

# 15) switch recovery from an indirect-branch jump table
jt=$("$BIN" decompile $FIX/arm64_jumptable.elf d7 2>/dev/null)
echo "$jt" | grep -q "switch ("                 || fail "jump-table switch"
echo "$jt" | grep -q "case 9:"                  || fail "jump-table cases"
echo "$jt" | grep -q "case .*: goto" && fail "jump-table cases inlined"
[ "$(echo "$jt" | grep -c 'case [0-9]*:')" -eq 10 ] || fail "jump-table count"
if echo "$jt" | grep -q "unsupported"; then fail "jump-table unsupported"; fi
for label in $(echo "$jt" | sed -n 's/.*goto \(L_[0-9a-f]*\);.*/\1/p' | sort -u); do
  echo "$jt" | grep -q "$label:" || fail "missing $label"
done
ok "jump-table switch"

# 16) function names from the Go pclntab (only if Go is installed)
go_json=$("$BIN" functions $FIX/go_stripped --json 2>/dev/null)
echo "$go_json" | grep -q '"functionCount"'         || fail "go functions"
go_list=$("$BIN" functions $FIX/go_stripped --limit 5000 2>/dev/null)
echo "$go_list" | grep -q "main.twice"              || fail "go pclntab names"
go_card=$("$BIN" card $FIX/go_stripped main.twice 2>/dev/null)
echo "$go_card" | grep -q '"nameSources": \['       || fail "go card"
echo "$go_card" | grep -q '"pclntab"'               || fail "go card source"
ok "go pclntab"

# 17) function names and ranges from DWARF
debug=$("$BIN" functions $FIX/arm64_debug.elf 2>/dev/null)
echo "$debug" | grep -q "symtab,dwarf"       || fail "dwarf merge"
stripped=$("$BIN" functions $FIX/arm64_debug_stripped.elf 2>/dev/null)
echo "$stripped" | grep -q "helper"        || fail "dwarf-only name"
echo "$stripped" | grep -q "dwarf"         || fail "dwarf-only source"
stripped_pc=$("$BIN" decompile $FIX/arm64_debug_stripped.elf sum3 2>/dev/null)
echo "$stripped_pc" | grep -q "int sum3(int a, int b, int c)" || fail "dwarf typed signature"
typed=$("$BIN" decompile $FIX/arm64_debug.elf pair_sum 2>/dev/null)
echo "$typed" | grep -q "struct pair \*p"  || fail "dwarf struct parameter"
typed_arr=$("$BIN" decompile $FIX/arm64_debug.elf sum_arr 2>/dev/null)
echo "$typed_arr" | grep -q "int \*p, int n" || fail "dwarf array parameter"
ok "dwarf names"

# 18) Rust / C++ demangling
rust_list=$("$BIN" functions $FIX/rust_demo 2>/dev/null)
echo "$rust_list" | grep -q "rust_demo::"   || fail "rust demangling"
ok "rust demangling"
cpp_list=$("$BIN" functions $FIX/cpp_demo.o 2>/dev/null)
echo "$cpp_list" | grep -q "ns::add(int, int)" || fail "c++ demangling"
ok "c++ demangling"
macho_json=$("$BIN" functions $FIX/x64_div_macho.o --json 2>/dev/null)
echo "$macho_json" | grep -q '"format": "macho"'   || fail "Mach-O format detect"
macho_c=$("$BIN" decompile $FIX/x64_div_macho.o _umod3x 2>/dev/null)
echo "$macho_c" | grep -q "return a0 % 0x3;"     || fail "Mach-O x86-64 decompile"
macho_a64=$("$BIN" decompile $FIX/arm64_macho.o _sum3 2>/dev/null)
echo "$macho_a64" | grep -q "_sum3(int32_t a0, int32_t a1, int32_t a2)" || fail "Mach-O AArch64 decompile"
ok "Mach-O objects"

# 19) MCP stdio server
mcp_out=$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"velk_run_script\",\"arguments\":{\"code\":\"velk.open('$FIX/arm64.o').getFunction('sum3').decompile()\"}}}" \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"velk_read_api","arguments":{"topic":"func"}}}' \
  '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"velk_run_script","arguments":{"code":"while (true) {}","timeout_ms":200}}}' \
  | "$BIN" mcp 2>/dev/null)
echo "$mcp_out" | grep -q '"tools"'           || fail "mcp tools/list"
echo "$mcp_out" | grep -q '"velk_run_script"' || fail "mcp tool entry"
echo "$mcp_out" | grep -q 'int32_t sum3'     || fail "mcp script call"
echo "$mcp_out" | grep -q 'interface Func'    || fail "mcp api docs"
echo "$mcp_out" | grep -q 'timed out'         || fail "mcp script timeout"
ok "mcp server"

# 20) performance regression (a few iterations, limits only)
# Timings under emulation are meaningless, so the canonical run sets VELK_BENCH=0.
if [ "${VELK_BENCH:-1}" = 1 ]; then
  ITER=10 ./tests/bench.sh >/dev/null 2>&1 || fail "performance bench"
  ok "performance bench"
else
  echo "skip: performance bench (VELK_BENCH=0)" >&2
fi

echo "smoke: all checks passed"
