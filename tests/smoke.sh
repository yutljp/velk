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
  echo "$navigation" | grep '"failures": \[\]' >/dev/null || fail "$operation navigation"
done
navigation=$("$BIN" --path "$FIX/tail_calls.o" tail_two tail_one --depth 1)
echo "$navigation" | grep '"path"' >/dev/null || fail "call path"
navigation=$("$BIN" --strings "$FIX/arm64_linked.elf" --contains velk-aarch64-string)
echo "$navigation" | grep 'velk-aarch64-string' >/dev/null || fail "string navigation"
navigation=$("$BIN" --constants "$FIX/tail_calls.o" 0x1)
echo "$navigation" | grep '"instruction"' >/dev/null || fail "constant navigation"
ok "navigation flags"

# Annotation flags and a writable project location.
project_file=tests/out/smoke-project.json
rm -f "$project_file"
"$BIN" --export-project "$FIX/arm64.o" --project "$project_file" >/dev/null
"$BIN" --annotations "$FIX/arm64.o" --project "$project_file" | grep '\[\]' >/dev/null || fail "empty annotations"
origins=$("$BIN" --origins "$FIX/arm64.o" sum3 --project "$project_file")
echo "$origins" | grep '"target"' >/dev/null || fail "origins"
"$BIN" --annotate "$FIX/arm64.o" '{"target":{"kind":"comment","address":"0x0"},"text":"analysis"}' --project "$project_file" >/dev/null
"$BIN" --annotation "$FIX/arm64.o" '{"kind":"comment","address":"0x0"}' --project "$project_file" | grep analysis >/dev/null || fail "annotation"
"$BIN" --import-project "$FIX/arm64.o" "$project_file" --project "$project_file" >/dev/null
"$BIN" --unannotate "$FIX/arm64.o" '{"kind":"comment","address":"0x0"}' --project "$project_file" | grep true >/dev/null || fail "unannotate"
rm -f "$project_file"
ok "annotation flags"

# 1) PE64: format, ISA, function count
pe_json=$("$BIN" --functions $FIX/pe64.exe --json 2>/dev/null)
echo "$pe_json" | grep '"format": "pe"'          >/dev/null || fail "PE format detect"
echo "$pe_json" | grep '"arch": "x86_64"'        >/dev/null || fail "PE64 isa detect"
function_count=$(echo "$pe_json" | sed -n 's/.*"functionCount": \([0-9]*\).*/\1/p')
[ -n "$function_count" ] && [ "$function_count" -ge 3 ]                     || fail "PE64 function discovery (n=$function_count)"
ok "PE64 functions (n_functions=$function_count)"

# 2) PE64: function card contract
card=$("$BIN" --card $FIX/pe64.exe reg_add --budget 144 2>/dev/null)
echo "$card" | grep '"name": "reg_add"'          >/dev/null || fail "card name"
echo "$card" | grep '"sizeEstimated": true'      >/dev/null || fail "card size estimation"
echo "$card" | grep 'lea eax'                    >/dev/null || fail "PE64 decode (lea eax)"
ok "PE64 card (reg_add)"

# 3) AArch64 ELF: overlapping section resolution and decoding
arm_json=$("$BIN" --functions $FIX/arm64.o --json 2>/dev/null)
echo "$arm_json" | grep '"arch": "aarch64"'      >/dev/null || fail "AArch64 isa detect"
arm_card=$("$BIN" --card $FIX/arm64.o sum3 --budget 144 2>/dev/null)
echo "$arm_card" | grep '"section": ".text"'     >/dev/null || fail "AArch64 section resolution (.text)"
echo "$arm_card" | grep 'add w0, w8, w2'         >/dev/null || fail "AArch64 decode"
echo "$arm_card" | grep '"blocks"'               >/dev/null || fail "function card IR summary"
ok "AArch64 functions/card"

# 4) AArch64 IR: arithmetic, constants, branches, loads, explicit unsupported markers
sum3_ir=$("$BIN" --ir $FIX/arm64.o sum3 2>/dev/null)
echo "$sum3_ir" | grep "fn sum3"                     >/dev/null || fail "ir sum3 header"
[ "$(echo "$sum3_ir" | grep -o ' + ' | wc -l | tr -d ' ')" -ge 2 ] || fail "ir sum3 adds"
echo "$sum3_ir" | grep 'ret .*w2'                   >/dev/null || fail "ir sum3 ret"
ok "ir sum3"

helper_ir=$("$BIN" --ir $FIX/arm64.o helper 2>/dev/null)
echo "$helper_ir" | grep 'brif lt'                  >/dev/null || fail "ir helper branch"
echo "$helper_ir" | grep -- '-> 0x48'               >/dev/null || fail "ir helper target"
echo "$helper_ir" | grep '0x555'                   >/dev/null || fail "ir helper constant"
echo "$helper_ir" | grep 'v1 = '                   >/dev/null || fail "ir helper assignment"
ok "ir helper"

arr_ir=$("$BIN" --ir $FIX/arm64.o sum_arr 2>/dev/null)
echo "$arr_ir" | grep 'load32'                      >/dev/null || fail "ir sum_arr load"
echo "$arr_ir" | grep 'add_lanes32'                 >/dev/null || fail "ir sum_arr vector add"
ok "ir sum_arr"

# 5) pseudo-C output
sum3_c=$("$BIN" --decompile $FIX/arm64.o sum3 2>/dev/null)
echo "$sum3_c" | grep "int32_t sum3(uint32_t a0, uint32_t a1, uint32_t a2)" >/dev/null || fail "decompile sum3 signature"
echo "$sum3_c" | grep "return a1 + a0 + a2;"   >/dev/null || fail "decompile sum3 fold"
[ "$(echo "$sum3_c" | grep -c '0xffffffff')" -eq 0 ] || fail "decompile sum3 masks"
echo "$sum3_c" | grep "return "               >/dev/null || fail "decompile sum3 return"
echo "$sum3_ir" | grep -F "ret (((w1 + w0) + w2) & #0xffffffff)" >/dev/null || fail "ir sum3 width"
while IFS='|' read -r action name pattern label; do
  case "$action" in
    decompile)
      arithmetic_output=$("$BIN" --decompile "$FIX/$pattern" "$label" 2>/dev/null)
      printf -v "$name" '%s' "$arithmetic_output"
      ;;
    match)
      echo "${!name}" | grep "$pattern" >/dev/null || fail "$label"
      ;;
    reject)
      if echo "${!name}" | grep "$pattern" >/dev/null; then fail "$label"; fi
      ;;
  esac
done <<'ARITHMETIC'
decompile|div_ir|arm64_div.o|udiv3
match|div_ir|a0 / 3|magic unsigned div
decompile|sd_ir|arm64_div.o|sdiv3
match|sd_ir|int32_t|magic signed type
match|sd_ir|a0 / 3|magic signed div
decompile|hd_ir|arm64_div.o|hdiv3
match|hd_ir|a0 / 3|magic 64bit div
match|hd_ir|uint64_t|magic 64bit width
decompile|sd_ir|arm64_div.o|sdiv10
match|sd_ir|a0 / 10|magic signed scaled div10
match|sd_ir|int32_t|magic signed scaled width
decompile|sl_ir|arm64_div.o|sdiv16
match|sl_ir|a0 / 16|csel select signed div16
decompile|ll_ir|arm64_div.o|ldiv16
match|ll_ir|a0 / 16|csel select signed div16 long
decompile|um_ir|arm64_div.o|umod3
match|um_ir|a0 % 3|multiplier unwind mod u32
decompile|sm_ir|arm64_div.o|smod3
match|sm_ir|a0 % 3|multiplier unwind mod s32
match|sm_ir|int32_t|multiplier unwind width
decompile|lm_ir|arm64_div.o|lmod3
match|lm_ir|a0 % 3|multiplier unwind mod s64
match|lm_ir|int64_t|multiplier unwind width 64
decompile|um10|arm64_div.o|umod10
match|um10|a0 % 10|multiplier unwind mod u32 10
decompile|lm10|arm64_div.o|lmod10
match|lm10|a0 % 10|msub unwind mod s64 10
decompile|um10b|arm64_div.o|umod10b
match|um10b|a0 % 10|msub unwind mod u64 10
decompile|umx|x64_div.o|umod3x
match|umx|% 3|x86 lea unwind mod u32
decompile|smx|x64_div.o|smod3x
match|smx|% 3|x86 lea unwind mod s32
decompile|lmx|x64_div.o|lmod10x
decompile|lm16|arm64_div.o|lmod16
match|lm16|% 16|cset-pow2 mod s64
match|lm16|int64_t|cset-pow2 width 64
decompile|sm4|arm64_div.o|smod4
decompile|sd16|arm64_div.o|sdiv16
match|sd16|int32_t|csel div16 dividend width
decompile|sm10|arm64_div.o|smod10
match|sm10|int32_t smod10|msub mod10 signed width
decompile|sm3x|x64_div.o|smod3x
decompile|ng|arm64_div.o|negate
match|ng|return -a0;|negate render
reject|ng|0 -|negate render kept 0 - x
match|sm3x|int32_t smod3x(|x86 lea mod3 signed width
match|sm4|% 4|cset-pow2 mod s32
match|sm4|int32_t|cset-pow2 width 32
match|lmx|% 10|x64 lea unwind mod s64
decompile|ld_ir|arm64_div.o|ldiv3
match|ld_ir|a0 / 3|magic signed 64bit div
match|ld_ir|int64_t|magic signed 64bit width
decompile|l10_ir|arm64_div.o|ldiv10
match|l10_ir|a0 / 10|magic signed 64bit div10
decompile|x64_l3|x64_div.o|l3
match|x64_l3|/ 3|x64 signed 64bit div
match|x64_l3|int64_t|x64 signed 64bit width
decompile|x64_h3|x64_div.o|h3
match|x64_h3|/ 3|x64 unsigned 64bit div
decompile|x64_sel|x64_div.o|pdiv64
match|x64_sel|/ 64|x64 signed select div
match|x64_sel|int32_t|x64 signed select width
decompile|x64_selq|x64_div.o|qdiv64
match|x64_selq|a0 / 64|x64 signed select 64bit div
decompile|x64_sel10|x64_div.o|pdiv10
match|x64_sel10|/ 10|x64 signed sext div10
ARITHMETIC
helper_cs=$("$BIN" --decompile $FIX/arm64.o helper 2>/dev/null)
echo "$helper_cs" | grep "uint32_t v8 = v2 >> 1;" >/dev/null || fail "shift has its own narrow variable"
echo "$helper_cs" | grep "(v8 + (v8 << 1))" >/dev/null || fail "32-bit read shared without a temporary"
ok "cse temps"
x64_fold=$("$BIN" --decompile $FIX/x64_div.o l3 2>/dev/null)
echo "$x64_fold" | grep "0xfffffffffffffff8" >/dev/null && fail "frame prologue elision"
echo "$x64_fold" | grep "rbp"                >/dev/null && fail "frame register elision"
echo "$x64_fold" | grep "a0 / 3"           >/dev/null || fail "copy propagation into division"
x64_mod=$("$BIN" --decompile $FIX/x64_div.o umod3x 2>/dev/null)
echo "$x64_mod" | grep "rcx"                 >/dev/null && fail "dead copy removal"
ok "x86 cleanup"
p8s=$("$BIN" --decompile $FIX/x64_div.o pmod8s 2>/dev/null)
echo "$p8s" | grep "a0 % 8"        >/dev/null || fail "x86 signed pow2 mod"
p16l=$("$BIN" --decompile $FIX/x64_div.o pmod16l 2>/dev/null)
echo "$p16l" | grep "a0 % 16"      >/dev/null || fail "x64 signed pow2 mod"
p8u=$("$BIN" --decompile $FIX/x64_div.o pmod8x 2>/dev/null)
echo "$p8u" | grep "a0 & 0x7"        >/dev/null || fail "x86 unsigned pow2 mask"
iz=$("$BIN" --decompile $FIX/arm64_div.o is_zero 2>/dev/null)
echo "$iz" | grep "a0 == 0"        >/dev/null || fail "cset eq compare"
ip=$("$BIN" --decompile $FIX/arm64_div.o is_pos 2>/dev/null)
echo "$ip" | grep "a0 > 0"         >/dev/null || fail "cset gt compare"
echo "$iz" | grep "return a0 == 0;" >/dev/null || fail "cset as a truth value"
ok "pow2 mod and cset"
locals=$("$BIN" --decompile $FIX/arm64_loops0.o count_bits 2>/dev/null)
echo "$locals" | grep "v2 = a0"     >/dev/null || fail "stack local naming"
echo "$locals" | grep "v2 >>= 1" >/dev/null || fail "stack local names one slot"
use_ir=$("$BIN" --decompile $FIX/cpp_demo.o "use(int)" 2>/dev/null)
echo "$use_ir" | grep "ns__mul(a0, 2)" >/dev/null || fail "C++ call relocation"
echo "$use_ir" | grep -E "(= x20|x20 =)" >/dev/null && fail "callee-save elision (x20)"
echo "$use_ir" | grep -E "(= x30|x30 =)" >/dev/null && fail "callee-save elision (x30)"
echo "$use_ir" | grep -E "(= x29|x29 =)" >/dev/null && fail "frame setup elision"
ok "callee-save elision"
fold_ret=$("$BIN" --decompile $FIX/x64_div.o umod3x 2>/dev/null)
echo "$fold_ret" | grep "return a0 % 3;"  >/dev/null || fail "temporary inlining into ret"
sum3_c=$("$BIN" --decompile $FIX/arm64.o sum3 2>/dev/null)
echo "$sum3_c" | grep "w8" >/dev/null && fail "temporary inlining (sum3)"
ok "temporary inlining"
abs_ir=$("$BIN" --decompile $FIX/pe64.exe reg_abs 2>/dev/null)
echo "$abs_ir" | grep -F "((int32_t)-(uint32_t)a0 < 0 ? a0 : -(uint32_t)a0)" >/dev/null || fail "neg and cmovs absolute value"
echo "$abs_ir" | grep -- "-(-" >/dev/null && fail "double negation kept"
sign_ir=$("$BIN" --decompile $FIX/pe64.exe reg_sign 2>/dev/null)
echo "$sign_ir" | grep "(int8_t)a0"   >/dev/null || fail "sign-extend mask fold"
echo "$sign_ir" | grep "0x1f" >/dev/null && fail "sign-extend artifact"
ok "algebraic cleanup"
abs_ret=$("$BIN" --decompile $FIX/pe64.exe reg_abs 2>/dev/null)
echo "$abs_ret" | grep -F "return ((int32_t)-(uint32_t)a0 < 0 ? a0 : -(uint32_t)a0);" >/dev/null || fail "abs folds into the return"
helper_cse=$("$BIN" --decompile $FIX/arm64.o helper 2>/dev/null)
echo "$helper_cse" | grep "t1" >/dev/null && fail "temporary for a 32-bit register read"
ok "two-round inlining"
div_ir=$("$BIN" --decompile $FIX/pe64.exe reg_div 2>/dev/null)
echo "$div_ir" | grep -F "return (int64_t)a0 / a1;" >/dev/null || fail "runtime division inlining"
mod_ir=$("$BIN" --decompile $FIX/pe64.exe reg_mod 2>/dev/null)
echo "$mod_ir" | grep -F "a0 % a1" >/dev/null || fail "idiv remainder dividend"
ok "runtime division and remainder"
stack_ir=$("$BIN" --decompile $FIX/arm64_loops0.o sum_until 2>/dev/null)
echo "$stack_ir" | grep -F "for (int32_t i = 1;" >/dev/null || fail "stack locals named"
echo "$stack_ir" | grep -F "result = (uint32_t)result + i;" >/dev/null || fail "stack local accumulation"
echo "$stack_ir" | grep "sp + 0x4" >/dev/null && fail "stack address left raw"
ok "stack locals"
decl_ir=$("$BIN" --decompile $FIX/arm64_loops0.o sum_until 2>/dev/null)
echo "$decl_ir" | grep -F "for (int32_t i = 1;" >/dev/null || fail "stack local declaration"
echo "$decl_ir" | grep "(i & 0xffffffff)" >/dev/null && fail "local mask elided"
echo "$decl_ir" | grep "w9" >/dev/null && fail "32-bit register left between two locals"
ok "stack local declarations"
frame_ir=$("$BIN" --decompile $FIX/arm64_loops0.o sum_until 2>/dev/null)
echo "$frame_ir" | grep -E "^ *sp = " >/dev/null && fail "frame adjustments hidden"
echo "$frame_ir" | grep "sp + 0x4" >/dev/null && fail "frame slot canonicalized"
loop_ir=$("$BIN" --decompile $FIX/cpp_demo.o "use(int)" 2>/dev/null)
echo "$loop_ir" | grep "for (;;)" >/dev/null && fail "tail call read as a loop"
echo "$loop_ir" | grep "ns__mul("  >/dev/null || fail "relocated call target"
ok "frame settling and endless loop"
arr_ir=$("$BIN" --decompile $FIX/arm64.o sum_arr 2>/dev/null)
echo "$arr_ir" | grep "goto L_" >/dev/null && fail "sum_arr has no gotos"
echo "$arr_ir" | grep "} else {"   >/dev/null || fail "if/else across a skipped block"
echo "$arr_ir" | grep -F "v2 = (uint32_t)a1 & 0x7ffffff8;"   >/dev/null || fail "branch block prefix kept"
helper_pre=$("$BIN" --decompile $FIX/arm64.o helper 2>/dev/null)
echo "$helper_pre" | grep -F "v1 = (uint32_t)a0 - 1;" >/dev/null || fail "prefix before early return"
ok "if/else structuring"
sig_zero=$("$BIN" --decompile $FIX/arm64_div.o is_zero 2>/dev/null)
echo "$sig_zero" | grep "int32_t is_zero(int32_t a0)" >/dev/null || fail "boolean signature by usage"
sig_mul=$("$BIN" --decompile $FIX/pe64.exe reg_mul 2>/dev/null)
echo "$sig_mul" | grep "int32_t reg_mul(uint32_t a0, uint32_t a1)" >/dev/null || fail "mul signature by usage"
sig_h=$("$BIN" --decompile $FIX/x64_div.o h10 2>/dev/null)
echo "$sig_h" | grep -E "uint64_t _?h10\(uint64_t a0\)" >/dev/null || fail "wide signature kept"
sig_helper=$("$BIN" --decompile $FIX/arm64.o helper 2>/dev/null)
echo "$sig_helper" | grep "int32_t helper(int32_t a0)"    >/dev/null || fail "loop signature by usage"
ok "types by usage"
mask_ir=$("$BIN" --decompile $FIX/arm64.o helper 2>/dev/null)
echo "$mask_ir" | grep -F "return (v3 >> 1) * 0x55555556 + a0" >/dev/null || fail "mask implied by 32-bit arithmetic"
echo "$mask_ir" | grep -F "v2 = (uint64_t)v1 * ((uint32_t)a0 - 2);" >/dev/null || fail "64-bit product of 32-bit values"
echo "$mask_ir" | grep "v1 = (uint32_t)a0 - 1;"          >/dev/null || fail "mask implied by a 32-bit parameter"
narrow_ir=$("$BIN" --decompile $FIX/arm64_loops0.o sum_until 2>/dev/null)
echo "$narrow_ir" | grep "for (int32_t i = 1; i <= a0; i = (uint32_t)i + 1)" >/dev/null || fail "32-bit comparison kept"
echo "$narrow_ir" | grep "result = (uint32_t)result + i;"   >/dev/null || fail "wrapping update in a loop"
ok "mask elision by width"
narrow_dest=$("$BIN" --decompile $FIX/arm64.o helper 2>/dev/null)
echo "$narrow_dest" | grep "+ (v8 << 1)) - 1;" >/dev/null || fail "mask implied by the return type"
echo "$narrow_dest" | grep "a0 = .*0xffffffff" >/dev/null && fail "return mask kept"
ok "masks implied by the destination"
masked_ir=$("$BIN" --decompile $FIX/arm64.o sum_arr 2>/dev/null)
echo "$masked_ir" | grep -E "v3 = v[0-9]+ \+ v3;" >/dev/null || fail "unsigned accumulator cast not removed"
echo "$masked_ir" | grep "w10 + w8) & 0xffffffff" >/dev/null && fail "bounded mask kept"
ok "mask bounded by the constant"
dwarf_ir=$("$BIN" --decompile $FIX/arm64_debug.elf helper 2>/dev/null)
echo "$dwarf_ir" | grep "v1 = (uint32_t)x - 1;"      >/dev/null || fail "narrow DWARF type read without a mask"
echo "$dwarf_ir" | grep "(x & 0xffffffff)" >/dev/null && fail "narrow DWARF type keeps the mask"
ok "narrow DWARF types"
sign_c=$("$BIN" --decompile $FIX/pe64.exe reg_sign 2>/dev/null)
echo "$sign_c" | grep "(int8_t)a0;"           >/dev/null || fail "sign-extended value needs no mask"
echo "$sign_c" | grep "(int8_t)a0 & 0xffffffff" >/dev/null && fail "sign-extend mask kept"
ok "sign-extended widths"
degraded=$("$BIN" --decompile $FIX/arm64_debug.o sum3 2>/dev/null)
echo "$degraded" | grep "clang version" >/dev/null && fail "relocated DWARF name leaked"
echo "$degraded" | grep "int sum3(int a, int b, int c)" >/dev/null || fail "relocated DWARF signature"
ok "relocated DWARF in an object"
field_ir=$("$BIN" --decompile $FIX/arm64_debug.elf pair_sum 2>/dev/null)
echo "$field_ir" | grep "p->a"   >/dev/null || fail "DWARF field name for the first member"
echo "$field_ir" | grep "p->b"   >/dev/null || fail "DWARF field name for the second member"
echo "$field_ir" | grep "f_" >/dev/null && fail "member kept its offset name"
ok "DWARF member names"
zero_ir=$("$BIN" --decompile $FIX/arm64.o helper 2>/dev/null)
echo "$zero_ir" | grep "return 0;" >/dev/null || fail "zero stays a constant"
brk_ir=$("$BIN" --decompile $FIX/arm64_loops.o sum_until_zero 2>/dev/null)
echo "$brk_ir" | grep "do {"            >/dev/null || fail "bottom-tested loop formed"
echo "$brk_ir" | grep "break;"          >/dev/null || fail "loop exit reads as break"
echo "$brk_ir" | grep "goto L_" >/dev/null && fail "loop exit kept a goto"
echo "$brk_ir" | grep "unsupported" >/dev/null && fail "bic still unsupported"
echo "$brk_ir" | grep "~("              >/dev/null || fail "complement rendered"
ok "bottom-tested loops"
neg_ir=$("$BIN" --decompile $FIX/arm64_loops.o sum_till_neg 2>/dev/null)
# Clang 18's AArch64 sequence loses the signed-load/compare hint; retain the
# stable parameter identities while leaving that type precision unresolved.
echo "$neg_ir" | grep "sum_till_neg(uint32_t \*a0," >/dev/null || fail "fall-through pointer parameter kept"
echo "$neg_ir" | grep " a1)" >/dev/null || fail "fall-through scalar parameter kept"
echo "$neg_ir" | grep "break;"   >/dev/null || fail "top-tested break kept"
ok "fall-through predecessors"
simd_ir=$("$BIN" --decompile $FIX/arm64.o sum_arr 2>/dev/null)
echo "$simd_ir" | grep -A1 "if (a1 < 1) {" | grep "x8 = 0;" >/dev/null && fail "dead store before return in a SIMD function"
echo "$simd_ir" | grep "return 0;" >/dev/null || fail "early return kept"
ok "dead stores beside unmodeled code"
wide_ir=$("$BIN" --decompile $FIX/x64_div.o umod10x 2>/dev/null)
echo "$wide_ir" | grep "unsigned __int128" >/dev/null || fail "wide multiply uses a widened product"
echo "$wide_ir" | grep ">> 64" >/dev/null || fail "wide multiply selects the high half"
echo "$wide_ir" | grep " hi128 " >/dev/null && fail "wide multiply kept the infix"
ok "wide multiply"
settled=$("$BIN" --decompile $FIX/arm64_loops0.o sum_till_neg 2>/dev/null)
echo "$settled" | grep -F " = a0[i];" >/dev/null || fail "frame settled past a pointer load"
echo "$settled" | grep "sp = sp"           >/dev/null && fail "stack adjustments kept"
ok "frame settling past pointer bases"
narrow_dst=$("$BIN" --decompile $FIX/arm64_loops.o sum_till_neg 2>/dev/null)
echo "$narrow_dst" | grep "v3 = v2;" >/dev/null || fail "loop result variable"
echo "$narrow_dst" | grep "return v3;" >/dev/null || fail "loop result read back"
ok "narrow destination names"
trap_ir=$("$BIN" --decompile $FIX/go_stripped internal/abi.Kind.String 2>/dev/null)
echo "$trap_ir" | grep "runtime_panicIndex(0, a1, 0);" >/dev/null || fail "call that never returns kept"
echo "$trap_ir" | grep "__builtin_trap();" >/dev/null && fail "trap after a call that never returns"
pure_virtual=$("$BIN" --decompile $FIX/cpp_virtual_x64.elf __cxa_pure_virtual 2>/dev/null)
echo "$pure_virtual" | grep "__builtin_trap();" >/dev/null || fail "trap rendered"
echo "$pure_virtual" | grep -c "__builtin_trap();" | grep -x 1 >/dev/null || fail "trap padding collapsed"
echo "$trap_ir" | grep "Int3" >/dev/null && fail "int3 note kept"
echo "$trap_ir" | grep "local_0;" >/dev/null && fail "unused local declared"
ok "trap padding and unused locals"
back_ir=$("$BIN" --decompile $FIX/arm64_loops0.o sum_till_neg 2>/dev/null)
echo "$back_ir" | grep "for (i = 0; i < a1; i++) {" >/dev/null || fail "unconditional back edge structured"
echo "$back_ir" | grep "goto " >/dev/null && fail "early exit as a return"
echo "$back_ir" | grep "^L_c0:"         >/dev/null && fail "loop header kept as a label"
uv run python - "$back_ir" <<'PY'
import re, sys
body = sys.argv[1]
gotos = set(re.findall(r'goto (L_[0-9a-f]+);', body))
labels = set(re.findall(r'^\s*(L_[0-9a-f]+):', body, flags=re.M))
assert not (gotos - labels), f"dangling goto {gotos - labels}"
PY
ok "unconditional back edges"
opt0=$("$BIN" --decompile $FIX/arm64_loops0.o count_bits 2>/dev/null)
echo "$opt0" | grep "sp = sp" >/dev/null && fail "frame settled at -O0"
zero_ir=$("$BIN" --decompile $FIX/arm64.o sum_arr 2>/dev/null)
echo "$zero_ir" | grep "^int32_t sum_arr"  >/dev/null || fail "return type follows the value"
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
echo "$loops" | grep "do {"        >/dev/null || fail "stripped object body structured"
echo "$loops" | grep "break;"      >/dev/null || fail "stripped object loop exit"
ok "stripped relocatable objects"
x86_function_count=$("$BIN" --functions $FIX/x64_loops_stripped.o 2>/dev/null | sed -n '1s/.*functions: \([0-9]*\).*/\1/p')
[ "$x86_function_count" = "4" ] || fail "stripped x86 object function count ($x86_function_count)"
ok "stripped x86 objects"
# A tail call (`b` to another function) ends a function without a `ret`.
tail_function_count=$("$BIN" --functions $FIX/tail_calls_stripped.o 2>/dev/null | sed -n '1s/.*functions: \([0-9]*\).*/\1/p')
[ "$tail_function_count" = "3" ] || fail "tail call boundary ($tail_function_count)"
tail_addr=$("$BIN" --functions $FIX/tail_calls_stripped.o 2>/dev/null | tail -n +3 | sed -n 2p | awk '{print $1}')
tail_mid=$("$BIN" --decompile $FIX/tail_calls_stripped.o "$tail_addr" 2>/dev/null)
echo "$tail_mid" | grep "for (;;)" >/dev/null && fail "unresolved tail call became a loop"
echo "$tail_mid" | grep "();"        >/dev/null || fail "unresolved tail call rendered"
ok "tail call boundaries"
# An indirect tail call (`br x2`) also ends a function.
indirect_tail_function_count=$("$BIN" --functions $FIX/tail_indirect_stripped.o 2>/dev/null | sed -n '1s/.*functions: \([0-9]*\).*/\1/p')
[ "$indirect_tail_function_count" = "2" ] || fail "indirect tail call boundary ($indirect_tail_function_count)"
ok "indirect tail calls"
# A value just stored into a slot feeds its reader directly.
fwd=$("$BIN" --decompile $FIX/arm64_loops0.o sum_till_neg 2>/dev/null)
echo "$fwd" | grep "x8 = i;" >/dev/null && fail "store not forwarded"
echo "$fwd" | grep -E 'result \+= v[0-9]+;' >/dev/null || fail "forwarded value missing"
pe_entry=$("$BIN" --functions $FIX/pe64.exe --json 2>/dev/null | sed -n 's/.*"entry": "\(0x[0-9a-f]*\)".*/\1/p')
entry_fwd=$("$BIN" --decompile $FIX/pe64.exe "$pe_entry" 2>/dev/null)
echo "$entry_fwd" | grep -F "*(uint32_t *)&local_0 = 35;" >/dev/null || fail "partial store into a wider local"
echo "$entry_fwd" | grep "return local_0;" >/dev/null || fail "pop reads the pushed slot"
echo "$entry_fwd" | grep "= rax;" >/dev/null && fail "overwritten push kept"
ok "stored values forwarded"










































entry_ir=$("$BIN" --decompile $FIX/pe64.exe "$pe_entry" 2>/dev/null)
echo "$entry_ir" | grep "rax = local_0;" >/dev/null && fail "dead frame load removed"
echo "$entry_ir" | grep "local_2" >/dev/null && fail "spurious slot after settling"
ok "dead frame loads"
moved_ir=$("$BIN" --decompile $FIX/arm64_loops0.o sum_until 2>/dev/null)
echo "$moved_ir" | grep "x8 = 1;" >/dev/null && fail "dead store before the loop"
echo "$moved_ir" | grep "i = 1;" >/dev/null || fail "live store before the loop"
live_ir=$("$BIN" --decompile $FIX/cpp_demo.o "use(int)" 2>/dev/null)
echo "$live_ir" | grep -F "ns__add(a0 & 0xffffffff, ((uint32_t)(ns__mul(a0, 2))));" >/dev/null || fail "definition kept across a call"
echo "$live_ir" | grep "v1 = a0;" >/dev/null && fail "saved value folded into the parameter"
ok "flow-sensitive dead stores"


pair_ir=$("$BIN" --decompile $FIX/arm64.o pair_sum 2>/dev/null)
echo "$pair_ir" | grep "a0->f_0"   >/dev/null || fail "member access at offset zero"
echo "$pair_ir" | grep "a0->f_4"   >/dev/null || fail "member access at offset four"
echo "$pair_ir" | grep "\*(uint32_t \*)" >/dev/null && fail "member access keeps the cast"
ok "pointer members"
msg_ir=$("$BIN" --decompile $FIX/pe64.exe msg_first 2>/dev/null)
echo "$msg_ir" | grep -F "extern uint64_t g_140003000;" >/dev/null || fail "global declaration by address"
echo "$msg_ir" | grep "(0x140003000)" >/dev/null && fail "global name replaces the address"
ok "named globals"
bits_ir=$("$BIN" --decompile $FIX/arm64_loops0.o count_bits 2>/dev/null)
echo "$bits_ir" | grep -F "result += (v2 & 0x1);" >/dev/null || fail "promoted add"
echo "$bits_ir" | grep -F "& 0x1)" >/dev/null || fail "promoted add operand"
echo "$bits_ir" | grep -F "v2 >>= 1;" >/dev/null || fail "shift assignment"
echo "$bits_ir" | grep "result = (result" >/dev/null && fail "compound add kept the temp"
ok "compound assignment"



































ok "decompile sum3"

helper_c=$("$BIN" --decompile $FIX/arm64.o helper 2>/dev/null)
echo "$helper_c" | grep "if (a0 < 1)"         >/dev/null || fail "decompile helper branch"
echo "$helper_c" | grep "return "               >/dev/null || fail "decompile helper return"
ok "decompile helper"

sum_arr_c=$("$BIN" --decompile $FIX/arm64.o sum_arr 2>/dev/null)
echo "$sum_arr_c" | grep "uint32_t \*a0"         >/dev/null || fail "pointer parameter typing"
echo "$sum_arr_c" | grep "sum_lanes32("            >/dev/null || fail "decompile sum_arr vector sum"
echo "$sum_arr_c" | grep -E 'uint64_t \*v[0-9]+( =|;)' >/dev/null || fail "decompile sum_arr vector pair load"
echo "$sum_arr_c" | grep "return 0;"           >/dev/null || fail "decompile sum_arr early return"
echo "$sum_arr_c" | grep "do {"                  >/dev/null || fail "decompile sum_arr loop"
echo "$sum_arr_c" | grep "} while ("             >/dev/null || fail "decompile sum_arr loop condition"
ok "decompile sum_arr"

# 6) x86-64 IR and pseudo-C
x86_ir=$("$BIN" --ir $FIX/pe64.exe reg_add 2>/dev/null)
echo "$x86_ir" | grep -F "ret ((rcx + rdx) & #0xffffffff)" >/dev/null || fail "x86 ir reg_add"
ok "x86 ir reg_add"

x86_mul=$("$BIN" --ir $FIX/pe64.exe reg_mul 2>/dev/null)
echo "$x86_mul" | grep " \* "                 >/dev/null || fail "x86 ir imul"
ok "x86 ir imul"
coff=$("$BIN" --decompile $FIX/pe64.obj reg_add 2>/dev/null)
echo "$coff" | grep -E 'reg_add\([^,]+, [^,]+\)'            >/dev/null || fail "COFF uses the Windows argument registers"
zeroed=$("$BIN" --decompile $FIX/l2_loop_x64.o find_first 2>/dev/null)
echo "$zeroed" | grep -E 'find_first\([^,]+, [^,]+, [^,]+\)' >/dev/null || fail "xor zeroing is not an argument read"
ok "argument registers"

x86_sign=$("$BIN" --decompile $FIX/pe64.exe reg_sign 2>/dev/null)
echo "$x86_sign" | grep "int8_t"             >/dev/null || fail "x86 movsx byte"
echo "$x86_sign" | grep "int16_t"            >/dev/null || fail "x86 movsx word"
ok "x86 lift sign extension"

x86_max=$("$BIN" --decompile $FIX/pe64.exe reg_max 2>/dev/null)
echo "$x86_max" | grep " ? "              >/dev/null || fail "x86 cmov select"
x86_abs=$("$BIN" --decompile $FIX/pe64.exe reg_abs 2>/dev/null)
echo "$x86_abs" | grep " ? "              >/dev/null || fail "x86 neg/cmov select"
if echo "$x86_abs" | grep "unsupported: cmov" >/dev/null; then fail "x86 cmov unresolved"; fi
ok "x86 cmov / setcc"

x86_div=$("$BIN" --decompile $FIX/pe64.exe reg_div 2>/dev/null)
echo "$x86_div" | grep " / "              >/dev/null || fail "x86 idiv quotient"
x86_mod=$("$BIN" --decompile $FIX/pe64.exe reg_mod 2>/dev/null)
echo "$x86_mod" | grep " % "              >/dev/null || fail "x86 idiv remainder"
if echo "$x86_div" | grep "unsupported" >/dev/null; then fail "x86 idiv unresolved"; fi
ok "x86 idiv"

closed_pipe=$( { "$BIN" --functions $FIX/go_probe --limit 100000 | head -1 >/dev/null || true; } 2>&1 )
[ -z "$closed_pipe" ] || fail "closed pipe reports an error"
ok "closed pipe"

x86_c=$("$BIN" --decompile $FIX/pe64.exe reg_add 2>/dev/null)
echo "$x86_c" | grep "int32_t reg_add(uint32_t a0, uint32_t a1)" >/dev/null || fail "x86 decompile signature"
echo "$x86_c" | grep "return a0 + a1;"         >/dev/null || fail "x86 decompile return"
ok "x86 decompile"

# 7) short bodies confirm callees without supplying names
"$BIN" --build-signatures $FIX/arm64.o --output $SIGS 2>/dev/null
[ -s $SIGS ]                          || fail "build-signatures output"
grep -q '"name": "helper"' $SIGS      || fail "build-signatures entry helper"
grep -q '"name": "sum3"' $SIGS || fail "short callee body missing"
ident=$("$BIN" --identify $FIX/alt.o --signatures $SIGS 2>/dev/null)
if echo "$ident" | grep "sum3" >/dev/null; then fail "short match accepted"; fi
echo "$ident" | grep "helper"                    >/dev/null || fail "identify helper instructions"
echo "$ident" | grep "identified 1 of 2"         >/dev/null || fail "identify count"
ok "build-signatures / identify"

# 8) while structuring (header condition and back edge)
loop_pc=$("$BIN" --decompile $FIX/arm64_loops0.o count_bits 2>/dev/null)
echo "$loop_pc" | grep -F "while (v2 != 0)" >/dev/null || fail "while structuring"
echo "$loop_pc" | grep "if (x8 == 0) break;" >/dev/null && fail "while header folded"
loop_break=$("$BIN" --decompile $FIX/arm64_loops0.o sum_until 2>/dev/null)
echo "$loop_break" | grep "i <= a0;" >/dev/null || fail "while break condition"
ok "while structuring"

# 9) data (string) reference recovery
msg=$("$BIN" --decompile $FIX/pe64.exe msg_first 2>/dev/null)
echo "$msg" | grep 'velk-ref-string'       >/dev/null || fail "string reference"
msg_card=$("$BIN" --card $FIX/pe64.exe msg_first 2>/dev/null)
echo "$msg_card" | grep 'velk-ref-string'  >/dev/null || fail "card string reference"
echo "$msg_card" | grep 'velk_ref_string'   >/dev/null || fail "card name hint"
ok "string references"

# A format's arguments past the registers are read from the stack
fmt_c=$("$BIN" --decompile $FIX/cold_gcc lookup 2>/dev/null)
echo "$fmt_c" | grep -F '"missing key %d among %d", a2 & 0xffffffff, a1);' >/dev/null || fail "variadic stack argument"
ok "variadic stack arguments"

# 10) struct access recovery
pair=$("$BIN" --decompile $FIX/arm64.o pair_sum 2>/dev/null)
pair_tag=$(echo "$pair" | sed -n 's/.*pair_sum(struct \([A-Za-z_][A-Za-z_0-9]*\) \*a0).*/\1/p')
[ -n "$pair_tag" ] || fail "struct parameter type"
echo "$pair" | grep -F "struct $pair_tag {" >/dev/null || fail "struct definition"
echo "$pair" | grep " uint32_t f_4; " >/dev/null || fail "struct access offsets"
pair_card=$("$BIN" --card $FIX/arm64.o pair_sum 2>/dev/null)
echo "$pair_card" | grep '"accesses"'    >/dev/null || fail "card struct accesses"
ok "struct access recovery"

# 11) AArch64 linked ELF: adrp/add and string references
linked=$("$BIN" --decompile $FIX/arm64_linked.elf pick 2>/dev/null)
echo "$linked" | grep 'velk-aarch64-string' >/dev/null || fail "adrp string reference"
ok "adrp / string reference"

# 12) applying a signature database (--signatures)
"$BIN" --build-signatures $FIX/arm64.o --output $SIGS 2>/dev/null
applied=$("$BIN" --decompile $FIX/alt.o alt_helper --signatures $SIGS 2>/dev/null)
echo "$applied" | grep "identified: helper"  >/dev/null || fail "decompile signature matching"
applied_card=$("$BIN" --card $FIX/alt.o alt_helper --signatures $SIGS 2>/dev/null)
echo "$applied_card" | grep '"identified": "helper"' >/dev/null || fail "card signature matching"
ok "signature application"

# 13) typed pointer parameters and the script API (shape hash, signature)
pair_c=$("$BIN" --decompile $FIX/arm64.o pair_sum 2>/dev/null)
echo "$pair_c" | grep -E 'struct [A-Za-z_][A-Za-z_0-9]* \*a0'  >/dev/null || fail "typed pointer parameter"
script=$(mktemp)
printf '%s\n' "const f = velk.open('$FIX/arm64.o').getFunction('pair_sum');" \
  'console.log(f.shapeHash().length, f.signature().params.length);' > "$script"
api=$("$BIN" --run "$script" 2>/dev/null)
rm -f "$script"
[ "$api" = "16 1" ]                              || fail "script API (got: $api)"
ok "script API"

# 14) extend-and-shift addressing (value-table switch)
switch_c=$("$BIN" --decompile $FIX/arm64_switch.elf dispatch 2>/dev/null)
echo "$switch_c" | grep "g_200120\[v1\]"   >/dev/null || fail "extend-shift addressing as a table"
echo "$switch_c" | grep "ref: 0x"                >/dev/null || fail "switch table reference"
if echo "$switch_c" | grep "unsupported:" >/dev/null; then fail "switch table unsupported"; fi
ok "table-driven switch"

# 15) switch recovery from an indirect-branch jump table
jump_table_c=$("$BIN" --decompile $FIX/arm64_jumptable.elf d7 2>/dev/null)
echo "$jump_table_c" | grep -F 'if ((uint32_t)a0 <= 9)' >/dev/null || fail "jump-table bounds"
[ "$(echo "$jump_table_c" | grep -Fc 'result = g;')" -eq 1 ] || fail "jump-table shared load"
for limit in {0..8}; do
  echo "$jump_table_c" | grep -F "if ((uint32_t)a0 > $limit)" >/dev/null || fail "jump-table case $limit"
done
if echo "$jump_table_c" | grep "unsupported" >/dev/null; then fail "jump-table unsupported"; fi
for label in $(echo "$jump_table_c" | sed -n 's/.*goto \(L_[0-9a-f]*\);.*/\1/p' | sort -u); do
  echo "$jump_table_c" | grep "$label:" >/dev/null || fail "missing $label"
done
ok "jump-table switch"

# 16) function names from the Go pclntab in the checked-in fixtures
go_json=$("$BIN" --functions $FIX/go_stripped --json 2>/dev/null)
echo "$go_json" | grep '"functionCount"'         >/dev/null || fail "go functions"
go_list=$("$BIN" --functions $FIX/go_stripped --limit 5000 2>/dev/null)
grep -q "main.twice" <<<"$go_list"               || fail "go pclntab names"
go_card=$("$BIN" --card $FIX/go_stripped main.twice 2>/dev/null)
echo "$go_card" | grep '"nameSources": \['       >/dev/null || fail "go card"
echo "$go_card" | grep '"pclntab"'               >/dev/null || fail "go card source"
ok "go pclntab"

# 17) function names and ranges from DWARF
debug=$("$BIN" --functions $FIX/arm64_debug.elf 2>/dev/null)
echo "$debug" | grep "symtab,dwarf"       >/dev/null || fail "dwarf merge"
stripped=$("$BIN" --functions $FIX/arm64_debug_stripped.elf 2>/dev/null)
echo "$stripped" | grep "helper"        >/dev/null || fail "dwarf-only name"
echo "$stripped" | grep "dwarf"         >/dev/null || fail "dwarf-only source"
stripped_pc=$("$BIN" --decompile $FIX/arm64_debug_stripped.elf sum3 2>/dev/null)
echo "$stripped_pc" | grep "int sum3(int a, int b, int c)" >/dev/null || fail "dwarf typed signature"
typed=$("$BIN" --decompile $FIX/arm64_debug.elf pair_sum 2>/dev/null)
echo "$typed" | grep "struct pair \*p"  >/dev/null || fail "dwarf struct parameter"
typed_arr=$("$BIN" --decompile $FIX/arm64_debug.elf sum_arr 2>/dev/null)
echo "$typed_arr" | grep "int \*p, int n" >/dev/null || fail "dwarf array parameter"
ok "dwarf names"

# 18) Rust / C++ demangling
rust_list=$("$BIN" --functions $FIX/rust_demo 2>/dev/null)
echo "$rust_list" | grep "rust_demo::"   >/dev/null || fail "rust demangling"
ok "rust demangling"
cpp_list=$("$BIN" --functions $FIX/cpp_demo.o 2>/dev/null)
echo "$cpp_list" | grep "ns::add(int, int)" >/dev/null || fail "c++ demangling"
ok "c++ demangling"
macho_json=$("$BIN" --functions $FIX/x64_div_macho.o --json 2>/dev/null)
echo "$macho_json" | grep '"format": "macho"'   >/dev/null || fail "Mach-O format detect"
macho_c=$("$BIN" --decompile $FIX/x64_div_macho.o _umod3x 2>/dev/null)
echo "$macho_c" | grep "return a0 % 3;"     >/dev/null || fail "Mach-O x86-64 decompile"
macho_a64=$("$BIN" --decompile $FIX/arm64_macho.o _sum3 2>/dev/null)
echo "$macho_a64" | grep "sum3(uint32_t a0, uint32_t a1, uint32_t a2)" >/dev/null || fail "Mach-O AArch64 decompile"
macho_c_name=$("$BIN" --decompile $FIX/arm64_macho.o sum3 2>/dev/null)
[ "$macho_a64" = "$macho_c_name" ] || fail "Mach-O C name lookup"
echo "$macho_json" | grep '"name": "_umod3x"' >/dev/null || fail "Mach-O listing link name"
ok "Mach-O objects"

# 18b) landing pads from the exception tables
pad=$($BIN --decompile tests/fixtures/rust_probe_stripped 0x4d240)
echo "$pad" | grep 'landing pad: an exception thrown by a call at 0x4d24a-0x4d250' >/dev/null || fail "landing pad note"
echo "$pad" | grep -F '_Unwind_Resume((void *)velk_exception_value());' >/dev/null || fail "landing pad exception"
ok "landing pads"

# 18c) indirect calls whose callee read-only tables fix
virtual=$("$BIN" --decompile $FIX/cpp_virtual_x64_stripped.elf 0x201480 2>/dev/null)
echo "$virtual" | grep -E 'v3 = sub_201430\(v2\); /\* via vtable slot 2 \*/' >/dev/null || fail "virtual call through a known table"
open_virtual=$("$BIN" --decompile $FIX/cpp_virtual_x64_stripped.elf 0x201410 2>/dev/null)
echo "$open_virtual" | grep 'vtable slot 2: sub_201430, sub_201460' >/dev/null || fail "virtual call candidates"
ok "indirect calls"

# 19) MCP stdio server
mcp_out=$(printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"velk_run_script\",\"arguments\":{\"code\":\"velk.open('$FIX/arm64.o').getFunction('sum3').decompile()\"}}}" \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"velk_read_api","arguments":{"topic":"func"}}}' \
  '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"velk_run_script","arguments":{"code":"while (true) {}","timeout_ms":200}}}' \
  | "$BIN" --mcp 2>/dev/null)
echo "$mcp_out" | grep '"tools"'           >/dev/null || fail "mcp tools/list"
echo "$mcp_out" | grep '"velk_run_script"' >/dev/null || fail "mcp tool entry"
echo "$mcp_out" | grep 'int32_t sum3'     >/dev/null || fail "mcp script call"
echo "$mcp_out" | grep 'interface Func'    >/dev/null || fail "mcp api docs"
echo "$mcp_out" | grep 'timed out'         >/dev/null || fail "mcp script timeout"
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
