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
# A binary given in BIN is checked as built; otherwise the debug build is.
if [ -z "${BIN:-}" ]; then
  BIN=${CARGO_TARGET_DIR:-target}/debug/velk
  cargo build --quiet
fi
[ -x "$BIN" ] || fail "binary not built"

"$BIN" --help >tests/out/cli-help.txt
status=0
"$BIN" >tests/out/cli-stdout.txt 2>tests/out/cli-stderr.txt || status=$?
[ "$status" -eq 2 ] || fail "no arguments exit status"
[ ! -s tests/out/cli-stderr.txt ] || fail "no arguments stderr"
cmp -s tests/out/cli-help.txt tests/out/cli-stdout.txt || fail "no arguments help"
status=0
"$BIN" --unknown >tests/out/cli-stdout.txt 2>tests/out/cli-stderr.txt || status=$?
[ "$status" -eq 2 ] || fail "parse error exit status"
[ ! -s tests/out/cli-stdout.txt ] || fail "parse error stdout"
grep -q '^error:' tests/out/cli-stderr.txt || fail "parse error message"
grep -q 'Usage:' tests/out/cli-stderr.txt || fail "parse error usage"
grep -q -- '--help' tests/out/cli-stderr.txt || fail "parse error help hint"
ok "command-line help and errors"

# Navigation uses the same operation flags as the other commands.
for operation in xrefs callers callees summary; do
  navigation=$("$BIN" --"$operation" "$FIX/tail_calls.o" tail_one)
  echo "$navigation" | grep -q '"failures": \[\]' || fail "$operation navigation"
done
navigation=$("$BIN" --path "$FIX/tail_calls.o" tail_two tail_one --depth 1)
echo "$navigation" | grep -q '"path"' || fail "call path"
navigation=$("$BIN" --strings "$FIX/arm64_linked.elf" --contains velk-aarch64-string)
echo "$navigation" | grep -q 'velk-aarch64-string' || fail "string navigation"
navigation=$("$BIN" --constants "$FIX/tail_calls.o" 0x1)
echo "$navigation" | grep -q '"instruction"' || fail "constant navigation"
ok "navigation flags"

# Annotation flags and a writable project location.
project_file=tests/out/smoke-project.json
rm -f "$project_file"
"$BIN" --export-project "$FIX/arm64.o" --project "$project_file" >/dev/null
"$BIN" --annotations "$FIX/arm64.o" --project "$project_file" | grep -q '\[\]' || fail "empty annotations"
origins=$("$BIN" --origins "$FIX/arm64.o" sum3 --project "$project_file")
echo "$origins" | grep -q '"target"' || fail "origins"
"$BIN" --annotate "$FIX/arm64.o" '{"target":{"kind":"comment","address":"0x0"},"text":"analysis"}' --project "$project_file" >/dev/null
"$BIN" --annotation "$FIX/arm64.o" '{"kind":"comment","address":"0x0"}' --project "$project_file" | grep -q analysis || fail "annotation"
"$BIN" --import-project "$FIX/arm64.o" "$project_file" --project "$project_file" >/dev/null
"$BIN" --unannotate "$FIX/arm64.o" '{"kind":"comment","address":"0x0"}' --project "$project_file" | grep -q true || fail "unannotate"
rm -f "$project_file"
ok "annotation flags"

# 1) PE64: format, ISA, function count
pe_json=$("$BIN" --functions $FIX/pe64.exe --json 2>/dev/null)
echo "$pe_json" | grep -q '"format": "pe"'          || fail "PE format detect"
echo "$pe_json" | grep -q '"arch": "x86_64"'        || fail "PE64 isa detect"
nf=$(echo "$pe_json" | sed -n 's/.*"functionCount": \([0-9]*\).*/\1/p')
[ -n "$nf" ] && [ "$nf" -ge 3 ]                     || fail "PE64 function discovery (n=$nf)"
ok "PE64 functions (n_functions=$nf)"

# 2) PE64: function card contract
card=$("$BIN" --card $FIX/pe64.exe reg_add --budget 144 2>/dev/null)
echo "$card" | grep -q '"name": "reg_add"'          || fail "card name"
echo "$card" | grep -q '"sizeEstimated": true'      || fail "card size estimation"
echo "$card" | grep -q 'lea eax'                    || fail "PE64 decode (lea eax)"
ok "PE64 card (reg_add)"

# 3) AArch64 ELF: overlapping section resolution and decoding
arm_json=$("$BIN" --functions $FIX/arm64.o --json 2>/dev/null)
echo "$arm_json" | grep -q '"arch": "aarch64"'      || fail "AArch64 isa detect"
arm_card=$("$BIN" --card $FIX/arm64.o sum3 --budget 144 2>/dev/null)
echo "$arm_card" | grep -q '"section": ".text"'     || fail "AArch64 section resolution (.text)"
echo "$arm_card" | grep -q 'add w0, w8, w2'         || fail "AArch64 decode"
echo "$arm_card" | grep -q '"blocks"'               || fail "function card IR summary"
ok "AArch64 functions/card"

# 4) AArch64 IR: arithmetic, constants, branches, loads, explicit unsupported markers
sum3_ir=$("$BIN" --ir $FIX/arm64.o sum3 2>/dev/null)
echo "$sum3_ir" | grep -q "fn sum3"                     || fail "ir sum3 header"
[ "$(echo "$sum3_ir" | grep -o ' + ' | wc -l | tr -d ' ')" -ge 2 ] || fail "ir sum3 adds"
echo "$sum3_ir" | grep -q 'ret .*w2'                   || fail "ir sum3 ret"
ok "ir sum3"

helper_ir=$("$BIN" --ir $FIX/arm64.o helper 2>/dev/null)
echo "$helper_ir" | grep -q 'brif lt'                  || fail "ir helper branch"
echo "$helper_ir" | grep -q -- '-> 0x48'               || fail "ir helper target"
echo "$helper_ir" | grep -q '0x555'                   || fail "ir helper constant"
echo "$helper_ir" | grep -q 'v1 = '                   || fail "ir helper assignment"
ok "ir helper"

arr_ir=$("$BIN" --ir $FIX/arm64.o sum_arr 2>/dev/null)
echo "$arr_ir" | grep -q 'load32'                      || fail "ir sum_arr load"
echo "$arr_ir" | grep -q 'add_lanes32'                 || fail "ir sum_arr vector add"
ok "ir sum_arr"

# 5) pseudo-C output
c3=$("$BIN" --decompile $FIX/arm64.o sum3 2>/dev/null)
echo "$c3" | grep -q "int32_t sum3(int32_t a0, int32_t a1, int32_t a2)" || fail "decompile sum3 signature"
echo "$c3" | grep -q "return a1 + a0 + a2;"   || fail "decompile sum3 fold"
[ "$(echo "$c3" | grep -c '0xffffffff')" -eq 0 ] || fail "decompile sum3 masks"
echo "$c3" | grep -q "return "               || fail "decompile sum3 return"
echo "$sum3_ir" | grep -qF "ret (((w1 + w0) + w2) & #0xffffffff)" || fail "ir sum3 width"
div_ir=$("$BIN" --decompile $FIX/arm64_div.o udiv3 2>/dev/null)
echo "$div_ir" | grep -q "a0 / 3"       || fail "magic unsigned div"
sd_ir=$("$BIN" --decompile $FIX/arm64_div.o sdiv3 2>/dev/null)
echo "$sd_ir" | grep -q "int32_t"        || fail "magic signed type"
echo "$sd_ir" | grep -q "a0 / 3"       || fail "magic signed div"
hd_ir=$("$BIN" --decompile $FIX/arm64_div.o hdiv3 2>/dev/null)
echo "$hd_ir" | grep -q "a0 / 3"        || fail "magic 64bit div"
echo "$hd_ir" | grep -q "uint64_t"       || fail "magic 64bit width"
sd_ir=$("$BIN" --decompile $FIX/arm64_div.o sdiv10 2>/dev/null)
echo "$sd_ir" | grep -q "a0 / 10"        || fail "magic signed scaled div10"
echo "$sd_ir" | grep -q "int32_t"        || fail "magic signed scaled width"
sl_ir=$("$BIN" --decompile $FIX/arm64_div.o sdiv16 2>/dev/null)
echo "$sl_ir" | grep -q "a0 / 16"      || fail "csel select signed div16"
ll_ir=$("$BIN" --decompile $FIX/arm64_div.o ldiv16 2>/dev/null)
echo "$ll_ir" | grep -q "a0 / 16"      || fail "csel select signed div16 long"
um_ir=$("$BIN" --decompile $FIX/arm64_div.o umod3 2>/dev/null)
echo "$um_ir" | grep -q "a0 % 3"       || fail "multiplier unwind mod u32"
sm_ir=$("$BIN" --decompile $FIX/arm64_div.o smod3 2>/dev/null)
echo "$sm_ir" | grep -q "a0 % 3"     || fail "multiplier unwind mod s32"
echo "$sm_ir" | grep -q "int32_t"        || fail "multiplier unwind width"
lm_ir=$("$BIN" --decompile $FIX/arm64_div.o lmod3 2>/dev/null)
echo "$lm_ir" | grep -q "a0 % 3"       || fail "multiplier unwind mod s64"
echo "$lm_ir" | grep -q "int64_t"        || fail "multiplier unwind width 64"
um10=$("$BIN" --decompile $FIX/arm64_div.o umod10 2>/dev/null)
echo "$um10" | grep -q "a0 % 10"      || fail "multiplier unwind mod u32 10"
lm10=$("$BIN" --decompile $FIX/arm64_div.o lmod10 2>/dev/null)
echo "$lm10" | grep -q "a0 % 10"        || fail "msub unwind mod s64 10"
um10b=$("$BIN" --decompile $FIX/arm64_div.o umod10b 2>/dev/null)
echo "$um10b" | grep -q "a0 % 10"       || fail "msub unwind mod u64 10"
umx=$("$BIN" --decompile $FIX/x64_div.o umod3x 2>/dev/null)
echo "$umx" | grep -q "% 3"            || fail "x86 lea unwind mod u32"
smx=$("$BIN" --decompile $FIX/x64_div.o smod3x 2>/dev/null)
echo "$smx" | grep -q "% 3"            || fail "x86 lea unwind mod s32"
lmx=$("$BIN" --decompile $FIX/x64_div.o lmod10x 2>/dev/null)
lm16=$("$BIN" --decompile $FIX/arm64_div.o lmod16 2>/dev/null)
echo "$lm16" | grep -q "% 16"         || fail "cset-pow2 mod s64"
echo "$lm16" | grep -q "int64_t"        || fail "cset-pow2 width 64"
sm4=$("$BIN" --decompile $FIX/arm64_div.o smod4 2>/dev/null)
sd16=$("$BIN" --decompile $FIX/arm64_div.o sdiv16 2>/dev/null)
echo "$sd16" | grep -q "int32_t"        || fail "csel div16 dividend width"
sm10=$("$BIN" --decompile $FIX/arm64_div.o smod10 2>/dev/null)
echo "$sm10" | grep -q "int32_t smod10" || fail "msub mod10 signed width"
sm3x=$("$BIN" --decompile $FIX/x64_div.o smod3x 2>/dev/null)
ng=$("$BIN" --decompile $FIX/arm64_div.o negate 2>/dev/null)
echo "$ng" | grep -q "return -a0;"      || fail "negate render"
echo "$ng" | grep -q "0 -" && fail "negate render kept 0 - x"
echo "$sm3x" | grep -q "int32_t smod3x(" || fail "x86 lea mod3 signed width"
echo "$sm4" | grep -q "% 4"           || fail "cset-pow2 mod s32"
echo "$sm4" | grep -q "int32_t"         || fail "cset-pow2 width 32"
echo "$lmx" | grep -q "% 10"            || fail "x64 lea unwind mod s64"
ld_ir=$("$BIN" --decompile $FIX/arm64_div.o ldiv3 2>/dev/null)
echo "$ld_ir" | grep -q "a0 / 3"        || fail "magic signed 64bit div"
echo "$ld_ir" | grep -q "int64_t"        || fail "magic signed 64bit width"
l10_ir=$("$BIN" --decompile $FIX/arm64_div.o ldiv10 2>/dev/null)
echo "$l10_ir" | grep -q "a0 / 10"      || fail "magic signed 64bit div10"
x64_l3=$("$BIN" --decompile $FIX/x64_div.o l3 2>/dev/null)
echo "$x64_l3" | grep -q "/ 3"         || fail "x64 signed 64bit div"
echo "$x64_l3" | grep -q "int64_t"       || fail "x64 signed 64bit width"
x64_h3=$("$BIN" --decompile $FIX/x64_div.o h3 2>/dev/null)
echo "$x64_h3" | grep -q "/ 3"         || fail "x64 unsigned 64bit div"
x64_sel=$("$BIN" --decompile $FIX/x64_div.o pdiv64 2>/dev/null)
echo "$x64_sel" | grep -q "/ 64"        || fail "x64 signed select div"
echo "$x64_sel" | grep -q "int32_t"      || fail "x64 signed select width"
x64_selq=$("$BIN" --decompile $FIX/x64_div.o qdiv64 2>/dev/null)
echo "$x64_selq" | grep -q "a0 / 64"   || fail "x64 signed select 64bit div"
x64_sel10=$("$BIN" --decompile $FIX/x64_div.o pdiv10 2>/dev/null)
echo "$x64_sel10" | grep -q "/ 10"      || fail "x64 signed sext div10"
helper_cs=$("$BIN" --decompile $FIX/arm64.o helper 2>/dev/null)
echo "$helper_cs" | grep -q "uint32_t v8 = v2 >> 1;" || fail "shift has its own narrow variable"
echo "$helper_cs" | grep -q "(v8 + (v8 << 1))" || fail "32-bit read shared without a temporary"
ok "cse temps"
x64_fold=$("$BIN" --decompile $FIX/x64_div.o l3 2>/dev/null)
echo "$x64_fold" | grep -q "0xfffffffffffffff8" && fail "frame prologue elision"
echo "$x64_fold" | grep -q "rbp"                && fail "frame register elision"
echo "$x64_fold" | grep -q "a0 / 3"           || fail "copy propagation into division"
x64_mod=$("$BIN" --decompile $FIX/x64_div.o umod3x 2>/dev/null)
echo "$x64_mod" | grep -q "rcx"                 && fail "dead copy removal"
ok "x86 cleanup"
p8s=$("$BIN" --decompile $FIX/x64_div.o pmod8s 2>/dev/null)
echo "$p8s" | grep -q "a0 % 8"        || fail "x86 signed pow2 mod"
p16l=$("$BIN" --decompile $FIX/x64_div.o pmod16l 2>/dev/null)
echo "$p16l" | grep -q "a0 % 16"      || fail "x64 signed pow2 mod"
p8u=$("$BIN" --decompile $FIX/x64_div.o pmod8x 2>/dev/null)
echo "$p8u" | grep -q "a0 & 0x7"        || fail "x86 unsigned pow2 mask"
iz=$("$BIN" --decompile $FIX/arm64_div.o is_zero 2>/dev/null)
echo "$iz" | grep -q "a0 == 0"        || fail "cset eq compare"
ip=$("$BIN" --decompile $FIX/arm64_div.o is_pos 2>/dev/null)
echo "$ip" | grep -q "a0 > 0"         || fail "cset gt compare"
echo "$iz" | grep -q "return a0 == 0;" || fail "cset as a truth value"
ok "pow2 mod and cset"
locals=$("$BIN" --decompile $FIX/arm64_loops0.o count_bits 2>/dev/null)
echo "$locals" | grep -q "v2 = a0"     || fail "stack local naming"
echo "$locals" | grep -q "v2 >>= 1" || fail "stack local names one slot"
use_ir=$("$BIN" --decompile $FIX/cpp_demo.o "use(int)" 2>/dev/null)
echo "$use_ir" | grep -q "ns__mul(a0, 2)" || fail "C++ call relocation"
echo "$use_ir" | grep -qE "(= x20|x20 =)" && fail "callee-save elision (x20)"
echo "$use_ir" | grep -qE "(= x30|x30 =)" && fail "callee-save elision (x30)"
echo "$use_ir" | grep -qE "(= x29|x29 =)" && fail "frame setup elision"
ok "callee-save elision"
fold_ret=$("$BIN" --decompile $FIX/x64_div.o umod3x 2>/dev/null)
echo "$fold_ret" | grep -q "return a0 % 3;"  || fail "temporary inlining into ret"
sum3_ir2=$("$BIN" --decompile $FIX/arm64.o sum3 2>/dev/null)
echo "$sum3_ir2" | grep -q "w8" && fail "temporary inlining (sum3)"
ok "temporary inlining"
abs_ir=$("$BIN" --decompile $FIX/pe64.exe reg_abs 2>/dev/null)
echo "$abs_ir" | grep -q "(-a0 < 0 ? a0 : -a0)" || fail "neg and cmovs absolute value"
echo "$abs_ir" | grep -q -- "-(-" && fail "double negation kept"
sign_ir=$("$BIN" --decompile $FIX/pe64.exe reg_sign 2>/dev/null)
echo "$sign_ir" | grep -q "(int8_t)a0"   || fail "sign-extend mask fold"
echo "$sign_ir" | grep -q "0x1f" && fail "sign-extend artifact"
ok "algebraic cleanup"
abs_ret=$("$BIN" --decompile $FIX/pe64.exe reg_abs 2>/dev/null)
echo "$abs_ret" | grep -q "return (-a0 < 0 ? a0 : -a0);"     || fail "abs folds into the return"
helper_cse=$("$BIN" --decompile $FIX/arm64.o helper 2>/dev/null)
echo "$helper_cse" | grep -q "t1" && fail "temporary for a 32-bit register read"
ok "two-round inlining"
div_ir=$("$BIN" --decompile $FIX/pe64.exe reg_div 2>/dev/null)
echo "$div_ir" | grep -qF "return a0 / a1;" || fail "runtime division inlining"
mod_ir=$("$BIN" --decompile $FIX/pe64.exe reg_mod 2>/dev/null)
echo "$mod_ir" | grep -qF "a0 % a1" || fail "idiv remainder dividend"
ok "runtime division and remainder"
stack_ir=$("$BIN" --decompile $FIX/arm64_loops0.o sum_until 2>/dev/null)
echo "$stack_ir" | grep -qF "for (int32_t i = 1;" || fail "stack locals named"
echo "$stack_ir" | grep -q "result += i;" || fail "stack local accumulation"
echo "$stack_ir" | grep -q "sp + 0x4" && fail "stack address left raw"
ok "stack locals"
decl_ir=$("$BIN" --decompile $FIX/arm64_loops0.o sum_until 2>/dev/null)
echo "$decl_ir" | grep -qF "for (int32_t i = 1;" || fail "stack local declaration"
echo "$decl_ir" | grep -q "(i & 0xffffffff)" && fail "local mask elided"
echo "$decl_ir" | grep -q "w9" && fail "32-bit register left between two locals"
ok "stack local declarations"
frame_ir=$("$BIN" --decompile $FIX/arm64_loops0.o sum_until 2>/dev/null)
echo "$frame_ir" | grep -qE "^ *sp = " && fail "frame adjustments hidden"
echo "$frame_ir" | grep -q "sp + 0x4" && fail "frame slot canonicalized"
loop_ir=$("$BIN" --decompile $FIX/cpp_demo.o "use(int)" 2>/dev/null)
echo "$loop_ir" | grep -q "for (;;)" && fail "tail call read as a loop"
echo "$loop_ir" | grep -q "ns__mul("  || fail "relocated call target"
ok "frame settling and endless loop"
arr_ir=$("$BIN" --decompile $FIX/arm64.o sum_arr 2>/dev/null)
echo "$arr_ir" | grep -q "goto L_" && fail "sum_arr has no gotos"
echo "$arr_ir" | grep -q "} else {"   || fail "if/else across a skipped block"
echo "$arr_ir" | grep -qF "v2 = (uint32_t)a1 & 0x7ffffff8;"   || fail "branch block prefix kept"
helper_pre=$("$BIN" --decompile $FIX/arm64.o helper 2>/dev/null)
echo "$helper_pre" | grep -q "v1 = a0 - 1;"  || fail "prefix before early return"
ok "if/else structuring"
sig_zero=$("$BIN" --decompile $FIX/arm64_div.o is_zero 2>/dev/null)
echo "$sig_zero" | grep -q "int32_t is_zero(int32_t a0)" || fail "boolean signature by usage"
sig_mul=$("$BIN" --decompile $FIX/pe64.exe reg_mul 2>/dev/null)
echo "$sig_mul" | grep -q "int32_t reg_mul(int32_t a0, int32_t a1)" || fail "mul signature by usage"
sig_h=$("$BIN" --decompile $FIX/x64_div.o h10 2>/dev/null)
echo "$sig_h" | grep -qE "uint64_t _?h10\(uint64_t a0\)" || fail "wide signature kept"
sig_helper=$("$BIN" --decompile $FIX/arm64.o helper 2>/dev/null)
echo "$sig_helper" | grep -q "int32_t helper(int32_t a0)"    || fail "loop signature by usage"
ok "types by usage"
mask_ir=$("$BIN" --decompile $FIX/arm64.o helper 2>/dev/null)
echo "$mask_ir" | grep -qF "return (v3 >> 1) * 0x55555556 + a0" || fail "mask implied by 32-bit arithmetic"
echo "$mask_ir" | grep -qF "v2 = (uint64_t)v1 * ((a0 - 2) & 0xffffffff);" || fail "64-bit product of 32-bit values"
echo "$mask_ir" | grep -q "v1 = a0 - 1;"          || fail "mask implied by a 32-bit parameter"
narrow_ir=$("$BIN" --decompile $FIX/arm64_loops0.o sum_until 2>/dev/null)
echo "$narrow_ir" | grep -q "for (int32_t i = 1; i <= a0; i++)" || fail "32-bit comparison kept"
echo "$narrow_ir" | grep -q "result += i;"   || fail "compound store in a loop"
ok "mask elision by width"
narrow_dest=$("$BIN" --decompile $FIX/arm64.o helper 2>/dev/null)
echo "$narrow_dest" | grep -q "+ (v8 << 1)) - 1;" || fail "mask implied by the return type"
echo "$narrow_dest" | grep -q "a0 = .*0xffffffff" && fail "return mask kept"
ok "masks implied by the destination"
masked_ir=$("$BIN" --decompile $FIX/arm64.o sum_arr 2>/dev/null)
echo "$masked_ir" | grep -qE "v3 = v[0-9]+ \+ v3;" || fail "mask bounded by its constant"
echo "$masked_ir" | grep -q "w10 + w8) & 0xffffffff" && fail "bounded mask kept"
ok "mask bounded by the constant"
dwarf_ir=$("$BIN" --decompile $FIX/arm64_debug.elf helper 2>/dev/null)
echo "$dwarf_ir" | grep -q "v1 = x - 1;"      || fail "narrow DWARF type read without a mask"
echo "$dwarf_ir" | grep -q "(x & 0xffffffff)" && fail "narrow DWARF type keeps the mask"
ok "narrow DWARF types"
sign_ir2=$("$BIN" --decompile $FIX/pe64.exe reg_sign 2>/dev/null)
echo "$sign_ir2" | grep -q "(int8_t)a0;"           || fail "sign-extended value needs no mask"
echo "$sign_ir2" | grep -q "(int8_t)a0 & 0xffffffff" && fail "sign-extend mask kept"
ok "sign-extended widths"
degraded=$("$BIN" --decompile $FIX/arm64_debug.o sum3 2>/dev/null)
echo "$degraded" | grep -q "clang version" && fail "relocated DWARF name leaked"
echo "$degraded" | grep -q "int sum3(int a, int b, int c)" || fail "relocated DWARF signature"
ok "relocated DWARF in an object"
field_ir=$("$BIN" --decompile $FIX/arm64_debug.elf pair_sum 2>/dev/null)
echo "$field_ir" | grep -q "p->a"   || fail "DWARF field name for the first member"
echo "$field_ir" | grep -q "p->b"   || fail "DWARF field name for the second member"
echo "$field_ir" | grep -q "field_0x" && fail "member kept its offset name"
ok "DWARF member names"
zero_ir=$("$BIN" --decompile $FIX/arm64.o helper 2>/dev/null)
echo "$zero_ir" | grep -q "return 0;" || fail "zero stays a constant"
brk_ir=$("$BIN" --decompile $FIX/arm64_loops.o sum_until_zero 2>/dev/null)
echo "$brk_ir" | grep -q "do {"            || fail "bottom-tested loop formed"
echo "$brk_ir" | grep -q "break;"          || fail "loop exit reads as break"
echo "$brk_ir" | grep -q "goto L_" && fail "loop exit kept a goto"
echo "$brk_ir" | grep -q "unsupported" && fail "bic still unsupported"
echo "$brk_ir" | grep -q "~("              || fail "complement rendered"
ok "bottom-tested loops"
neg_ir=$("$BIN" --decompile $FIX/arm64_loops.o sum_till_neg 2>/dev/null)
# Clang 18's AArch64 sequence loses the signed-load/compare hint; retain the
# stable parameter identities while leaving that type precision unresolved.
echo "$neg_ir" | grep -q "sum_till_neg(uint32_t \*a0," || fail "fall-through pointer parameter kept"
echo "$neg_ir" | grep -q " a1)" || fail "fall-through scalar parameter kept"
echo "$neg_ir" | grep -q "break;"   || fail "top-tested break kept"
ok "fall-through predecessors"
simd_ir=$("$BIN" --decompile $FIX/arm64.o sum_arr 2>/dev/null)
echo "$simd_ir" | grep -A1 "if (a1 < 1) {" | grep -q "x8 = 0;" && fail "dead store before return in a SIMD function"
echo "$simd_ir" | grep -q "return 0;" || fail "early return kept"
ok "dead stores beside unmodeled code"
wide_ir=$("$BIN" --decompile $FIX/x64_div.o umod10x 2>/dev/null)
echo "$wide_ir" | grep -q "unsigned __int128" || fail "wide multiply uses a widened product"
echo "$wide_ir" | grep -q ">> 64" || fail "wide multiply selects the high half"
echo "$wide_ir" | grep -q " hi128 " && fail "wide multiply kept the infix"
ok "wide multiply"
settled=$("$BIN" --decompile $FIX/arm64_loops0.o sum_till_neg 2>/dev/null)
echo "$settled" | grep -qF " = a0[i];" || fail "frame settled past a pointer load"
echo "$settled" | grep -q "sp = sp"           && fail "stack adjustments kept"
ok "frame settling past pointer bases"
narrow_dst=$("$BIN" --decompile $FIX/arm64_loops.o sum_till_neg 2>/dev/null)
echo "$narrow_dst" | grep -q "v3 = v2;" || fail "loop result variable"
echo "$narrow_dst" | grep -q "return v3;" || fail "loop result read back"
ok "narrow destination names"
trap_ir=$("$BIN" --decompile $FIX/go_stripped internal/abi.Kind.String 2>/dev/null)
echo "$trap_ir" | grep -q "runtime_panicIndex(0, a1, 0);" || fail "call that never returns kept"
echo "$trap_ir" | grep -q "__builtin_trap();" && fail "trap after a call that never returns"
pure_virtual=$("$BIN" --decompile $FIX/cpp_virtual_x64.elf __cxa_pure_virtual 2>/dev/null)
echo "$pure_virtual" | grep -q "__builtin_trap();" || fail "trap rendered"
echo "$pure_virtual" | grep -c "__builtin_trap();" | grep -qx 1 || fail "trap padding collapsed"
echo "$trap_ir" | grep -q "Int3" && fail "int3 note kept"
echo "$trap_ir" | grep -q "local_0;" && fail "unused local declared"
ok "trap padding and unused locals"
back_ir=$("$BIN" --decompile $FIX/arm64_loops0.o sum_till_neg 2>/dev/null)
echo "$back_ir" | grep -q "for (i = 0; i < a1; i++) {" || fail "unconditional back edge structured"
echo "$back_ir" | grep -q "goto " && fail "early exit as a return"
echo "$back_ir" | grep -q "^L_c0:"         && fail "loop header kept as a label"
uv run python - "$back_ir" <<'PY'
import re, sys
body = sys.argv[1]
gotos = set(re.findall(r'goto (L_[0-9a-f]+);', body))
labels = set(re.findall(r'^\s*(L_[0-9a-f]+):', body, flags=re.M))
assert not (gotos - labels), f"dangling goto {gotos - labels}"
PY
ok "unconditional back edges"
opt0=$("$BIN" --decompile $FIX/arm64_loops0.o count_bits 2>/dev/null)
echo "$opt0" | grep -q "sp = sp" && fail "frame settled at -O0"
zero_ir=$("$BIN" --decompile $FIX/arm64.o sum_arr 2>/dev/null)
echo "$zero_ir" | grep -q "^int32_t sum_arr"  || fail "return type follows the value"
ok "value-width return types"
# A stripped relocatable object keeps no symbols and no entry point: the
# functions are found from the code itself.
n=$("$BIN" --functions $FIX/arm64_loops_stripped.o 2>/dev/null | sed -n '1s/.*functions: \([0-9]*\).*/\1/p')
[ "$n" = "4" ] || fail "stripped object function count ($n)"
first=$("$BIN" --functions $FIX/arm64_loops_stripped.o 2>/dev/null | awk 'NR == 3 { print $1 }')
[ "$first" = "0x0" ] || fail "stripped object starts at its first function"
# The address of the loop function depends on the compiler's layout, so
# take it from the listing instead of pinning it.
loop_addr=$("$BIN" --functions $FIX/arm64_loops_stripped.o 2>/dev/null | awk 'NR == 6 { print $1 }')
loops=$("$BIN" --decompile $FIX/arm64_loops_stripped.o "$loop_addr" 2>/dev/null)
echo "$loops" | grep -q "do {"        || fail "stripped object body structured"
echo "$loops" | grep -q "break;"      || fail "stripped object loop exit"
ok "stripped relocatable objects"
xs=$("$BIN" --functions $FIX/x64_loops_stripped.o 2>/dev/null | sed -n '1s/.*functions: \([0-9]*\).*/\1/p')
[ "$xs" = "4" ] || fail "stripped x86 object function count ($xs)"
ok "stripped x86 objects"
# A tail call (`b` to another function) ends a function without a `ret`.
tn=$("$BIN" --functions $FIX/tail_calls_stripped.o 2>/dev/null | sed -n '1s/.*functions: \([0-9]*\).*/\1/p')
[ "$tn" = "3" ] || fail "tail call boundary ($tn)"
tail_addr=$("$BIN" --functions $FIX/tail_calls_stripped.o 2>/dev/null | tail -n +3 | sed -n 2p | awk '{print $1}')
tail_mid=$("$BIN" --decompile $FIX/tail_calls_stripped.o "$tail_addr" 2>/dev/null)
echo "$tail_mid" | grep -q "for (;;)" && fail "unresolved tail call became a loop"
echo "$tail_mid" | grep -q "();"        || fail "unresolved tail call rendered"
ok "tail call boundaries"
# An indirect tail call (`br x2`) also ends a function.
in_n=$("$BIN" --functions $FIX/tail_indirect_stripped.o 2>/dev/null | sed -n '1s/.*functions: \([0-9]*\).*/\1/p')
[ "$in_n" = "2" ] || fail "indirect tail call boundary ($in_n)"
ok "indirect tail calls"
# A value just stored into a slot feeds its reader directly.
fwd=$("$BIN" --decompile $FIX/arm64_loops0.o sum_till_neg 2>/dev/null)
echo "$fwd" | grep -q "x8 = i;" && fail "store not forwarded"
echo "$fwd" | grep -qE 'result \+= v[0-9]+;' || fail "forwarded value missing"
pe_entry=$("$BIN" --functions $FIX/pe64.exe --json 2>/dev/null | sed -n 's/.*"entry": "\(0x[0-9a-f]*\)".*/\1/p')
entry_fwd=$("$BIN" --decompile $FIX/pe64.exe "$pe_entry" 2>/dev/null)
echo "$entry_fwd" | grep -qF "*(uint32_t *)&local_0 = 35;" || fail "partial store into a wider local"
echo "$entry_fwd" | grep -q "return local_0;" || fail "pop reads the pushed slot"
echo "$entry_fwd" | grep -q "= rax;" && fail "overwritten push kept"
ok "stored values forwarded"










































entry_ir=$("$BIN" --decompile $FIX/pe64.exe "$pe_entry" 2>/dev/null)
echo "$entry_ir" | grep -q "rax = local_0;" && fail "dead frame load removed"
echo "$entry_ir" | grep -q "local_2" && fail "spurious slot after settling"
ok "dead frame loads"
moved_ir=$("$BIN" --decompile $FIX/arm64_loops0.o sum_until 2>/dev/null)
echo "$moved_ir" | grep -q "x8 = 1;" && fail "dead store before the loop"
echo "$moved_ir" | grep -q "i = 1;" || fail "live store before the loop"
live_ir=$("$BIN" --decompile $FIX/cpp_demo.o "use(int)" 2>/dev/null)
echo "$live_ir" | grep -qF "ns__add(a0 & 0xffffffff, ((uint32_t)(ns__mul(a0, 2))));" || fail "definition kept across a call"
echo "$live_ir" | grep -q "v1 = a0;" && fail "saved value folded into the parameter"
ok "flow-sensitive dead stores"


pair_ir=$("$BIN" --decompile $FIX/arm64.o pair_sum 2>/dev/null)
echo "$pair_ir" | grep -q "a0->field_0x0"   || fail "member access at offset zero"
echo "$pair_ir" | grep -q "a0->field_0x4"   || fail "member access at offset four"
echo "$pair_ir" | grep -q "\*(uint32_t \*)" && fail "member access keeps the cast"
ok "pointer members"
msg_ir=$("$BIN" --decompile $FIX/pe64.exe msg_first 2>/dev/null)
echo "$msg_ir" | grep -qF "extern uint64_t g_140003000;" || fail "global declaration by address"
echo "$msg_ir" | grep -q "(0x140003000)" && fail "global name replaces the address"
ok "named globals"
bits_ir=$("$BIN" --decompile $FIX/arm64_loops0.o count_bits 2>/dev/null)
echo "$bits_ir" | grep -qF "result += (v2 & 0x1);" || fail "promoted add"
echo "$bits_ir" | grep -qF "& 0x1)" || fail "promoted add operand"
echo "$bits_ir" | grep -qF "v2 >>= 1;" || fail "shift assignment"
echo "$bits_ir" | grep -q "result = (result" && fail "compound add kept the temp"
ok "compound assignment"



































ok "decompile sum3"

ch=$("$BIN" --decompile $FIX/arm64.o helper 2>/dev/null)
echo "$ch" | grep -q "if (a0 < 1)"         || fail "decompile helper branch"
echo "$ch" | grep -q "return "               || fail "decompile helper return"
ok "decompile helper"

ca=$("$BIN" --decompile $FIX/arm64.o sum_arr 2>/dev/null)
echo "$ca" | grep -q "uint32_t \*a0"         || fail "pointer parameter typing"
echo "$ca" | grep -q "sum_lanes32("            || fail "decompile sum_arr vector sum"
echo "$ca" | grep -Eq 'uint64_t \*v[0-9]+( =|;)' || fail "decompile sum_arr vector pair load"
echo "$ca" | grep -q "return 0;"           || fail "decompile sum_arr early return"
echo "$ca" | grep -q "do {"                  || fail "decompile sum_arr loop"
echo "$ca" | grep -q "} while ("             || fail "decompile sum_arr loop condition"
ok "decompile sum_arr"

# 6) x86-64 IR and pseudo-C
x86_ir=$("$BIN" --ir $FIX/pe64.exe reg_add 2>/dev/null)
echo "$x86_ir" | grep -qF "ret ((rcx + rdx) & #0xffffffff)" || fail "x86 ir reg_add"
ok "x86 ir reg_add"

x86_mul=$("$BIN" --ir $FIX/pe64.exe reg_mul 2>/dev/null)
echo "$x86_mul" | grep -q " \* "                 || fail "x86 ir imul"
ok "x86 ir imul"
coff=$("$BIN" --decompile $FIX/pe64.obj reg_add 2>/dev/null)
echo "$coff" | grep -Eq 'reg_add\([^,]+, [^,]+\)'            || fail "COFF uses the Windows argument registers"
zeroed=$("$BIN" --decompile $FIX/l2_loop_x64.o find_first 2>/dev/null)
echo "$zeroed" | grep -Eq 'find_first\([^,]+, [^,]+, [^,]+\)' || fail "xor zeroing is not an argument read"
ok "argument registers"

x86_sign=$("$BIN" --decompile $FIX/pe64.exe reg_sign 2>/dev/null)
echo "$x86_sign" | grep -q "int8_t"             || fail "x86 movsx byte"
echo "$x86_sign" | grep -q "int16_t"            || fail "x86 movsx word"
ok "x86 lift sign extension"

x86_max=$("$BIN" --decompile $FIX/pe64.exe reg_max 2>/dev/null)
echo "$x86_max" | grep -q " ? "              || fail "x86 cmov select"
x86_abs=$("$BIN" --decompile $FIX/pe64.exe reg_abs 2>/dev/null)
echo "$x86_abs" | grep -q " ? "              || fail "x86 neg/cmov select"
if echo "$x86_abs" | grep -q "unsupported: cmov"; then fail "x86 cmov unresolved"; fi
ok "x86 cmov / setcc"

x86_div=$("$BIN" --decompile $FIX/pe64.exe reg_div 2>/dev/null)
echo "$x86_div" | grep -q " / "              || fail "x86 idiv quotient"
x86_mod=$("$BIN" --decompile $FIX/pe64.exe reg_mod 2>/dev/null)
echo "$x86_mod" | grep -q " % "              || fail "x86 idiv remainder"
if echo "$x86_div" | grep -q "unsupported"; then fail "x86 idiv unresolved"; fi
ok "x86 idiv"

closed_pipe=$( { "$BIN" --functions $FIX/go_probe --limit 100000 | head -1 >/dev/null || true; } 2>&1 )
[ -z "$closed_pipe" ] || fail "closed pipe reports an error"
ok "closed pipe"

x86_c=$("$BIN" --decompile $FIX/pe64.exe reg_add 2>/dev/null)
echo "$x86_c" | grep -q "int32_t reg_add(int32_t a0, int32_t a1)" || fail "x86 decompile signature"
echo "$x86_c" | grep -q "return a0 + a1;"         || fail "x86 decompile return"
ok "x86 decompile"

# 7) instruction signatures reject short functions and match full bodies
"$BIN" --build-signatures $FIX/arm64.o --output $SIGS 2>/dev/null
[ -s $SIGS ]                          || fail "build-signatures output"
grep -q '"name": "helper"' $SIGS      || fail "build-signatures entry helper"
if grep -q '"name": "sum3"' $SIGS; then fail "short signature accepted"; fi
ident=$("$BIN" --identify $FIX/alt.o --signatures $SIGS 2>/dev/null)
if echo "$ident" | grep -q "sum3"; then fail "short match accepted"; fi
echo "$ident" | grep -q "helper"                    || fail "identify helper instructions"
echo "$ident" | grep -q "identified 1 of 2"         || fail "identify count"
ok "build-signatures / identify"

# 8) while structuring (header condition and back edge)
loop_pc=$("$BIN" --decompile $FIX/arm64_loops0.o count_bits 2>/dev/null)
echo "$loop_pc" | grep -qF "while (v2 != 0)" || fail "while structuring"
echo "$loop_pc" | grep -q "if (x8 == 0) break;" && fail "while header folded"
loop_break=$("$BIN" --decompile $FIX/arm64_loops0.o sum_until 2>/dev/null)
echo "$loop_break" | grep -q "i <= a0;" || fail "while break condition"
ok "while structuring"

# 9) data (string) reference recovery
msg=$("$BIN" --decompile $FIX/pe64.exe msg_first 2>/dev/null)
echo "$msg" | grep -q 'velk-ref-string'       || fail "string reference"
msg_card=$("$BIN" --card $FIX/pe64.exe msg_first 2>/dev/null)
echo "$msg_card" | grep -q 'velk-ref-string'  || fail "card string reference"
echo "$msg_card" | grep -q 'velk_ref_string'   || fail "card name hint"
ok "string references"

# A format's arguments past the registers are read from the stack
fmt_c=$("$BIN" --decompile $FIX/cold_gcc lookup 2>/dev/null)
echo "$fmt_c" | grep -qF '"missing key %d among %d", a2 & 0xffffffff, a1);' || fail "variadic stack argument"
ok "variadic stack arguments"

# 10) struct access recovery
pair=$("$BIN" --decompile $FIX/arm64.o pair_sum 2>/dev/null)
echo "$pair" | grep -q "struct S1 {"  || fail "struct definition"
echo "$pair" | grep -q " int32_t field_0x4; " || fail "struct access offsets"
echo "$pair" | grep -q "pair_sum(struct S1 \*a0)" || fail "struct parameter type"
pair_card=$("$BIN" --card $FIX/arm64.o pair_sum 2>/dev/null)
echo "$pair_card" | grep -q '"accesses"'    || fail "card struct accesses"
ok "struct access recovery"

# 11) AArch64 linked ELF: adrp/add and string references
linked=$("$BIN" --decompile $FIX/arm64_linked.elf pick 2>/dev/null)
echo "$linked" | grep -q 'velk-aarch64-string' || fail "adrp string reference"
ok "adrp / string reference"

# 12) applying a signature database (--signatures)
"$BIN" --build-signatures $FIX/arm64.o --output $SIGS 2>/dev/null
applied=$("$BIN" --decompile $FIX/alt.o alt_helper --signatures $SIGS 2>/dev/null)
echo "$applied" | grep -q "identified: helper"  || fail "decompile signature matching"
applied_card=$("$BIN" --card $FIX/alt.o alt_helper --signatures $SIGS 2>/dev/null)
echo "$applied_card" | grep -q '"identified": "helper"' || fail "card signature matching"
ok "signature application"

# 13) typed pointer parameters and the script API (shape hash, signature)
pair_c=$("$BIN" --decompile $FIX/arm64.o pair_sum 2>/dev/null)
echo "$pair_c" | grep -q 'struct S1 \*a0'  || fail "typed pointer parameter"
script=$(mktemp)
printf '%s\n' "const f = velk.open('$FIX/arm64.o').getFunction('pair_sum');" \
  'console.log(f.shapeHash().length, f.signature().params.length);' > "$script"
api=$("$BIN" --run "$script" 2>/dev/null)
rm -f "$script"
[ "$api" = "16 1" ]                              || fail "script API (got: $api)"
ok "script API"

# 14) extend-and-shift addressing (value-table switch)
sw=$("$BIN" --decompile $FIX/arm64_switch.elf dispatch 2>/dev/null)
echo "$sw" | grep -q "g_200120\[v1\]"   || fail "extend-shift addressing as a table"
echo "$sw" | grep -q "ref: 0x"                || fail "switch table reference"
if echo "$sw" | grep -q "unsupported:"; then fail "switch table unsupported"; fi
ok "table-driven switch"

# 15) switch recovery from an indirect-branch jump table
jt=$("$BIN" --decompile $FIX/arm64_jumptable.elf d7 2>/dev/null)
echo "$jt" | grep -Fq 'if ((uint32_t)a0 <= 9)' || fail "jump-table bounds"
[ "$(echo "$jt" | grep -Fc 'v1 = g;')" -eq 1 ] || fail "jump-table shared load"
for limit in {0..8}; do
  echo "$jt" | grep -Fq "if ((uint32_t)a0 > $limit)" || fail "jump-table case $limit"
done
if echo "$jt" | grep -q "unsupported"; then fail "jump-table unsupported"; fi
for label in $(echo "$jt" | sed -n 's/.*goto \(L_[0-9a-f]*\);.*/\1/p' | sort -u); do
  echo "$jt" | grep -q "$label:" || fail "missing $label"
done
ok "jump-table switch"

# 16) function names from the Go pclntab (only if Go is installed)
go_json=$("$BIN" --functions $FIX/go_stripped --json 2>/dev/null)
echo "$go_json" | grep -q '"functionCount"'         || fail "go functions"
go_list=$("$BIN" --functions $FIX/go_stripped --limit 5000 2>/dev/null)
grep -q "main.twice" <<<"$go_list"               || fail "go pclntab names"
go_card=$("$BIN" --card $FIX/go_stripped main.twice 2>/dev/null)
echo "$go_card" | grep -q '"nameSources": \['       || fail "go card"
echo "$go_card" | grep -q '"pclntab"'               || fail "go card source"
ok "go pclntab"

# 17) function names and ranges from DWARF
debug=$("$BIN" --functions $FIX/arm64_debug.elf 2>/dev/null)
echo "$debug" | grep -q "symtab,dwarf"       || fail "dwarf merge"
stripped=$("$BIN" --functions $FIX/arm64_debug_stripped.elf 2>/dev/null)
echo "$stripped" | grep -q "helper"        || fail "dwarf-only name"
echo "$stripped" | grep -q "dwarf"         || fail "dwarf-only source"
stripped_pc=$("$BIN" --decompile $FIX/arm64_debug_stripped.elf sum3 2>/dev/null)
echo "$stripped_pc" | grep -q "int sum3(int a, int b, int c)" || fail "dwarf typed signature"
typed=$("$BIN" --decompile $FIX/arm64_debug.elf pair_sum 2>/dev/null)
echo "$typed" | grep -q "struct pair \*p"  || fail "dwarf struct parameter"
typed_arr=$("$BIN" --decompile $FIX/arm64_debug.elf sum_arr 2>/dev/null)
echo "$typed_arr" | grep -q "int \*p, int n" || fail "dwarf array parameter"
ok "dwarf names"

# 18) Rust / C++ demangling
rust_list=$("$BIN" --functions $FIX/rust_demo 2>/dev/null)
echo "$rust_list" | grep -q "rust_demo::"   || fail "rust demangling"
ok "rust demangling"
cpp_list=$("$BIN" --functions $FIX/cpp_demo.o 2>/dev/null)
echo "$cpp_list" | grep -q "ns::add(int, int)" || fail "c++ demangling"
ok "c++ demangling"
macho_json=$("$BIN" --functions $FIX/x64_div_macho.o --json 2>/dev/null)
echo "$macho_json" | grep -q '"format": "macho"'   || fail "Mach-O format detect"
macho_c=$("$BIN" --decompile $FIX/x64_div_macho.o _umod3x 2>/dev/null)
echo "$macho_c" | grep -q "return a0 % 3;"     || fail "Mach-O x86-64 decompile"
macho_a64=$("$BIN" --decompile $FIX/arm64_macho.o _sum3 2>/dev/null)
echo "$macho_a64" | grep -q "sum3(int32_t a0, int32_t a1, int32_t a2)" || fail "Mach-O AArch64 decompile"
macho_c_name=$("$BIN" --decompile $FIX/arm64_macho.o sum3 2>/dev/null)
[ "$macho_a64" = "$macho_c_name" ] || fail "Mach-O C name lookup"
echo "$macho_json" | grep -q '"name": "_umod3x"' || fail "Mach-O listing link name"
ok "Mach-O objects"

# 18b) landing pads from the exception tables
pad=$($BIN --decompile tests/fixtures/rust_probe_stripped 0x4d240)
echo "$pad" | grep -q 'landing pad: an exception thrown by a call at 0x4d24a-0x4d250' || fail "landing pad note"
echo "$pad" | grep -Fq '_Unwind_Resume((void *)velk_exception_value());' || fail "landing pad exception"
ok "landing pads"

# 18c) indirect calls whose callee read-only tables fix
virtual=$("$BIN" --decompile $FIX/cpp_virtual_x64_stripped.elf 0x201480 2>/dev/null)
echo "$virtual" | grep -qE 'v3 = sub_201430\(v2\); /\* via vtable slot 2 \*/' || fail "virtual call through a known table"
open_virtual=$("$BIN" --decompile $FIX/cpp_virtual_x64_stripped.elf 0x201410 2>/dev/null)
echo "$open_virtual" | grep -q 'vtable slot 2: sub_201430, sub_201460' || fail "virtual call candidates"
ok "indirect calls"

# 19) MCP stdio server
mcp_out=$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"velk_run_script\",\"arguments\":{\"code\":\"velk.open('$FIX/arm64.o').getFunction('sum3').decompile()\"}}}" \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"velk_read_api","arguments":{"topic":"func"}}}' \
  '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"velk_run_script","arguments":{"code":"while (true) {}","timeout_ms":200}}}' \
  | "$BIN" --mcp 2>/dev/null)
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
