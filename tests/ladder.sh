#!/usr/bin/env bash
# Difficulty ladder: check each expectation in tests/expect/ladder.tsv and
# print pass counts per level (L0..L7) and an overall score.
#
#   ./tests/ladder.sh           check only (exit code 1 on any FAIL)
#   ./tests/ladder.sh --build   rebuild the fixtures first
#   ./tests/ladder.sh --level 3 L3 only
#
# known_* rows are TODOs: the ideal output, not met yet. Once one passes,
# promote it to has/nothas (a passing known_* row is reported so it is not forgotten).
set -uo pipefail
cd "$(dirname "$0")/.."
FIX=${VELK_OUT:-tests/out}

BIN=${BIN:-${CARGO_TARGET_DIR:-target}/debug/velk}
EXPECT=tests/expect/ladder.tsv
BUILD=0
ONLY=

while [ $# -gt 0 ]; do
  case "$1" in
    --build) BUILD=1 ;;
    --level) shift; ONLY=${1:-} ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$BUILD" = 1 ] || [ ! -d tests/out ] || [ -z "$(ls -A tests/out 2>/dev/null)" ]; then
  ./tests/make_fixtures.sh >/dev/null || { echo "fixture build failed" >&2; exit 1; }
fi
cargo build --quiet || { echo "cargo build failed" >&2; exit 1; }
[ -x "$BIN" ] || { echo "missing $BIN" >&2; exit 1; }

# Toolchain each fixture needs. make_fixtures.sh records missing ones in
# $FIX/skipped.txt, and those rows are reported as SKIP instead of FAIL.
requires() {
  case "$1" in
    pe64.exe) echo pe64-link ;;
    arm64_linked.elf|arm64_jumptable.elf|arm64_switch.elf|l5_switch.elf) echo linked-elf ;;
    *stripped*) echo stripped ;;
    go_*) echo go ;;
    rust_*) echo rust ;;
    *) echo "" ;;
  esac
}
skips=$FIX/skipped.txt
skipped_tool() {  # tool -> true if not installed
  [ -f "$skips" ] && grep -qx "$1" "$skips" 2>/dev/null
}

rendered() {  # fixture function -> pseudo-C (function "-" gives the `functions` listing)
  local fixture=$1 function=$2
  if [ "$function" = "-" ]; then
    "$BIN" functions "$FIX/$fixture" --limit 100000 2>/dev/null
  else
    # Mach-O uses `_name` and ELF uses `name`, so try both.
    "$BIN" decompile "$FIX/$fixture" "$function" 2>/dev/null \
      || "$BIN" decompile "$FIX/$fixture" "_$function" 2>/dev/null \
      || "$BIN" decompile "$FIX/$fixture" "${function#_}" 2>/dev/null
  fi
}

results=$(mktemp)
trap 'rm -f "$results"' EXIT

while IFS=$'\t' read -r level fixture function kind pattern; do
  case "$level" in ''|'#'*) continue ;; esac
  [ -n "$ONLY" ] && [ "$level" != "$ONLY" ] && continue
  need=$(requires "$fixture")
  if { [ ! -f "$FIX/$fixture" ] || { [ -n "$need" ] && skipped_tool "$need"; }; }; then
    # A toolchain that is not installed is not a test failure.
    printf 'SKIP\t%s\t%s/%s\tnot built: %s missing\n' \
      "$level" "$fixture" "$function" "${need:-fixture}" >> "$results"
    continue
  fi
  out=$(rendered "$fixture" "$function")
  case "$kind" in
    count)
      got=$(sed -n '1s/.*functions: \([0-9]*\).*/\1/p' <<< "$out")
      [ "$got" = "$pattern" ] && ok=1 || ok=0
      detail="function count $got (expected $pattern)"
      ;;
    count_min)
      # The count depends on the host standard library, so check only a lower bound.
      got=$(sed -n '1s/.*functions: \([0-9]*\).*/\1/p' <<< "$out")
      [ -n "$got" ] && [ "$got" -ge "$pattern" ] && ok=1 || ok=0
      detail="function count $got (expected >= $pattern)"
      ;;
    has|known_has)
      printf '%s' "$out" | grep -qF "$pattern" && ok=1 || ok=0
      detail="contains '$pattern'"
      ;;
    has_any|known_has_any)
      # `A|B`: output varies by compiler, so any one alternative passes.
      ok=0
      old_ifs=$IFS; IFS='|'
      for candidate in $pattern; do
        IFS=$old_ifs
        printf '%s' "$out" | grep -qF "$candidate" && ok=1
        IFS='|'
      done
      IFS=$old_ifs
      detail="contains one of '$pattern'"
      ;;
    nothas|known_nothas)
      printf '%s' "$out" | grep -qF "$pattern" && ok=0 || ok=1
      detail="does not contain '$pattern'"
      ;;
    *) ok=0; detail="unknown kind: $kind" ;;
  esac
  case "$kind" in
    known_*)
      if [ "$ok" = 1 ]; then
        printf 'PROMOTE\t%s\t%s/%s\t%s\n' "$level" "$fixture" "$function" "$detail" >> "$results"
      else
        printf 'TODO\t%s\t%s/%s\t%s\n' "$level" "$fixture" "$function" "$detail" >> "$results"
      fi
      ;;
    *)
      if [ "$ok" = 1 ]; then
        printf 'PASS\t%s\t%s/%s\t%s\n' "$level" "$fixture" "$function" "$detail" >> "$results"
      else
        printf 'FAIL\t%s\t%s/%s\t%s\n' "$level" "$fixture" "$function" "$detail" >> "$results"
      fi
      ;;
  esac
done < "$EXPECT"

fixture_cc=$(head -1 $FIX/toolchain.txt 2>/dev/null || true)
echo "fixtures: ${fixture_cc:-unknown}"
echo "== passes per level =="
awk -F'\t' '{ t[$2]++; if ($1=="PASS"||$1=="PROMOTE") p[$2]++ }
  END { for (l=0; l<10; l++) if (t[l]) printf "  L%d  %2d/%2d\n", l, p[l]+0, t[l] }' "$results"

for status in SKIP FAIL TODO PROMOTE; do
  if grep -q "^$status	" "$results" 2>/dev/null; then
    case $status in
      SKIP)    echo; echo "== SKIP (toolchain not installed) ==" ;;
      FAIL)    echo; echo "== FAIL ==" ;;
      TODO)    echo; echo "== TODO (known_*: ideal not reached yet) ==" ;;
      PROMOTE) echo; echo "== PROMOTE (known_* passed: move to has/nothas) ==" ;;
    esac
    awk -F'\t' -v s="$status" '$1==s { printf "  L%s %s — %s\n", $2, $3, $4 }' "$results"
  fi
done

counts=$(awk -F'\t' '{ c[$1]++ } END { printf "%d %d %d %d", c["PASS"]+0, c["FAIL"]+0, c["TODO"]+0, c["SKIP"]+0 }' "$results")
set -- $counts
echo
echo "score: pass=$1 fail=$2 todo=$3 skip=$4"
[ "$2" -eq 0 ]
