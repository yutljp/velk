#!/usr/bin/env bash
# Difficulty ladder: check each expectation in tests/expect/ladder.tsv and
# print pass counts per level (L0..L7) and an overall score.
#
#   ./tests/ladder.sh            check every row (exit code 1 on any FAIL)
#   ./tests/ladder.sh --level 3  L3 only
#
# known_* rows are TODOs: the ideal output, not met yet. Once one passes,
# promote it to has/nothas (a passing known_* row is reported so it is not forgotten).
set -uo pipefail
cd "$(dirname "$0")/../.."
FIXTURES_DIR=tests/fixtures

BIN=${BIN:-}
EXPECT=tests/expect/ladder.tsv
ONLY_LEVEL=

while [ $# -gt 0 ]; do
  case "$1" in
    --level) shift; ONLY_LEVEL=${1:-} ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

# A binary given in BIN is checked as built; otherwise the debug build is.
if [ -z "$BIN" ]; then
  BIN=${CARGO_TARGET_DIR:-target}/debug/velk
  cargo build --quiet || { echo "cargo build failed" >&2; exit 1; }
fi
[ -x "$BIN" ] || { echo "missing $BIN" >&2; exit 1; }

rendered() {  # fixture function -> pseudo-C (function "-" gives the `functions` listing)
  local fixture=$1 function=$2
  if [ "$function" = "-" ]; then
    "$BIN" --functions "$FIXTURES_DIR/$fixture" --limit 100000 2>/dev/null
  else
    "$BIN" --decompile "$FIXTURES_DIR/$fixture" "$function" 2>/dev/null
  fi
}

results=$(mktemp)
trap 'rm -f "$results"' EXIT

while IFS=$'\t' read -r level fixture function kind pattern; do
  case "$level" in ''|'#'*) continue ;; esac
  [ -n "$ONLY_LEVEL" ] && [ "$level" != "$ONLY_LEVEL" ] && continue
  if [ ! -f "$FIXTURES_DIR/$fixture" ]; then
    printf 'FAIL\t%s\t%s/%s\tmissing fixture\n' "$level" "$fixture" "$function" >> "$results"
    continue
  fi
  out=$(rendered "$fixture" "$function")
  if [ "$kind" = count ] || [ "$kind" = count_min ]; then
    got=$(sed -n '1s/.*functions: \([0-9]*\).*/\1/p' <<< "$out")
  fi
  case "$kind" in
    count)
      [ "$got" = "$pattern" ] && ok=1 || ok=0
      detail="function count $got (expected $pattern)"
      ;;
    count_min)
      # The count depends on the host standard library, so check only a lower bound.
      [ -n "$got" ] && [ "$got" -ge "$pattern" ] && ok=1 || ok=0
      detail="function count $got (expected >= $pattern)"
      ;;
    has|known_has)
      grep -qF "$pattern" <<<"$out" && ok=1 || ok=0
      detail="contains '$pattern'"
      ;;
    has_any|known_has_any)
      # `A|B`: output varies by compiler, so any one alternative passes.
      ok=0
      old_ifs=$IFS; IFS='|'
      for candidate in $pattern; do
        IFS=$old_ifs
        grep -qF "$candidate" <<<"$out" && ok=1
        IFS='|'
      done
      IFS=$old_ifs
      detail="contains one of '$pattern'"
      ;;
    nothas|known_nothas)
      grep -qF "$pattern" <<<"$out" && ok=0 || ok=1
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

fixture_cc=$(head -1 $FIXTURES_DIR/toolchain.txt 2>/dev/null || true)
echo "fixtures: ${fixture_cc:-unknown}"
echo "== passes per level =="
awk -F'\t' '{ t[$2]++; if ($1=="PASS"||$1=="PROMOTE") p[$2]++ }
  END { for (l=0; l<10; l++) if (t[l]) printf "  L%d  %2d/%2d\n", l, p[l]+0, t[l] }' "$results"

for status in FAIL TODO PROMOTE; do
  if grep -q "^$status	" "$results" 2>/dev/null; then
    case $status in
      FAIL)    echo; echo "== FAIL ==" ;;
      TODO)    echo; echo "== TODO (known_*: ideal not reached yet) ==" ;;
      PROMOTE) echo; echo "== PROMOTE (known_* passed: move to has/nothas) ==" ;;
    esac
    awk -F'\t' -v s="$status" '$1==s { printf "  L%s %s — %s\n", $2, $3, $4 }' "$results"
  fi
done

counts=$(awk -F'\t' '{ c[$1]++ } END { printf "%d %d %d", c["PASS"]+0, c["FAIL"]+0, c["TODO"]+0 }' "$results")
set -- $counts
echo
echo "score: pass=$1 fail=$2 todo=$3"
[ "$2" -eq 0 ]
