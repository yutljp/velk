#!/usr/bin/env bash
# 難易度ラダー: tests/expect/ladder.tsv の期待値を1行ずつ評価し、
# 段(L0..L7)ごとの通過数と全体のスコアを出す。
#
#   ./tests/ladder.sh           評価だけ(FAIL があれば終了コード 1)
#   ./tests/ladder.sh --build   先にフィクスチャを作り直す
#   ./tests/ladder.sh --level 3 L3 だけ
#
# known_* の行は「理想の期待値だが現状は満たさない」TODO。満たすように
# なったら has/nothas に昇格させる(放置を検出するため、通ったら警告する)。
set -uo pipefail
cd "$(dirname "$0")/.."

BIN=${BIN:-target/debug/velk}
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

# フィクスチャが要求するツールチェーン。make_fixtures.sh が
# tests/out/skipped.txt に印を残すので、無い場合は FAIL ではなく SKIP にする。
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
skips=tests/out/skipped.txt
skipped_tool() {  # tool -> 導入されていないか
  [ -f "$skips" ] && grep -qx "$1" "$skips" 2>/dev/null
}

rendered() {  # fixture function -> 疑似 C (関数指定なしは inspect --limit)
  local fixture=$1 function=$2
  if [ "$function" = "-" ]; then
    "$BIN" inspect "tests/out/$fixture" --limit 100000 2>/dev/null
  else
    "$BIN" decompile "tests/out/$fixture" --name "$function" 2>/dev/null
  fi
}

results=$(mktemp)
trap 'rm -f "$results"' EXIT

while IFS=$'\t' read -r level fixture function kind pattern; do
  case "$level" in ''|'#'*) continue ;; esac
  [ -n "$ONLY" ] && [ "$level" != "$ONLY" ] && continue
  need=$(requires "$fixture")
  if { [ ! -f "tests/out/$fixture" ] || { [ -n "$need" ] && skipped_tool "$need"; }; }; then
    # A toolchain that is not installed is not a test failure.
    printf 'SKIP\t%s\t%s/%s\t%s が無いため未生成\n' \
      "$level" "$fixture" "$function" "${need:-fixture}" >> "$results"
    continue
  fi
  out=$(rendered "$fixture" "$function")
  case "$kind" in
    count)
      got=$(printf '%s\n' "$out" | head -1 | grep -o "functions: [0-9]*" | grep -o "[0-9]*")
      [ "$got" = "$pattern" ] && ok=1 || ok=0
      detail="関数数 $got (期待 $pattern)"
      ;;
    has|known_has)
      printf '%s' "$out" | grep -qF "$pattern" && ok=1 || ok=0
      detail="'$pattern' を含む"
      ;;
    nothas|known_nothas)
      printf '%s' "$out" | grep -qF "$pattern" && ok=0 || ok=1
      detail="'$pattern' を含まない"
      ;;
    *) ok=0; detail="未知の kind: $kind" ;;
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

echo "== 段ごとの通過 =="
awk -F'\t' '{ t[$2]++; if ($1=="PASS"||$1=="PROMOTE") p[$2]++ }
  END { for (l=0; l<10; l++) if (t[l]) printf "  L%d  %2d/%2d\n", l, p[l]+0, t[l] }' "$results"

for status in SKIP FAIL TODO PROMOTE; do
  if grep -q "^$status	" "$results" 2>/dev/null; then
    case $status in
      SKIP)    echo; echo "== SKIP (ツールチェーン未導入) ==" ;;
      FAIL)    echo; echo "== FAIL ==" ;;
      TODO)    echo; echo "== TODO (known_*: 理想には未到達) ==" ;;
      PROMOTE) echo; echo "== 昇格候補 (known_* が通った: has/nothas へ) ==" ;;
    esac
    awk -F'\t' -v s="$status" '$1==s { printf "  L%s %s — %s\n", $2, $3, $4 }' "$results"
  fi
done

counts=$(awk -F'\t' '{ c[$1]++ } END { printf "%d %d %d %d", c["PASS"]+0, c["FAIL"]+0, c["TODO"]+0, c["SKIP"]+0 }' "$results")
set -- $counts
echo
echo "score: pass=$1 fail=$2 todo=$3 skip=$4"
[ "$2" -eq 0 ]
