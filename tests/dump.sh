#!/usr/bin/env bash
# 疑似 C を関数ごとに書き出す。正本と手元の差分を取るための入力になる。
#
#   ./tests/dump.sh tests/out-canonical   # -> tests/out-canonical/dump/<fixture>/<function>.c
#
# 出力は「関数名と本文」だけにして、コメント中のアドレスなど環境で
# 変わりうる行は落とす（差分を意味のある差だけにするため）。
set -uo pipefail
cd "$(dirname "$0")/.."
FIX=${1:-${VELK_OUT:-tests/out}}
BIN=${BIN:-${CARGO_TARGET_DIR:-target}/debug/velk}
[ -x "$BIN" ] || { echo "missing $BIN" >&2; exit 1; }
[ -d "$FIX" ] || { echo "missing fixture dir $FIX" >&2; exit 1; }

out=$FIX/dump
rm -rf "$out"
mkdir -p "$out"

count=0
for fixture in "$FIX"/*; do
  [ -f "$fixture" ] || continue
  case "$fixture" in
    */dump|*/skipped.txt|*/toolchain.txt|*/ladder.txt) continue ;;
  esac
  name=$(basename "$fixture")
  mkdir -p "$out/$name"
  # 関数の一覧は inspect から取る（名前が無い像ではアドレスで引く）。
  "$BIN" inspect "$fixture" --limit 100000 2>/dev/null | tail -n +3 \
    | awk '{print $1"\t"$3}' | while IFS=$'\t' read -r addr symbol; do
        [ -n "$addr" ] || continue
        key=${symbol}
        case "$symbol" in
          "<unnamed>"|"") key=$addr ;;
        esac
        # Go のシンボルは `pkg/path.Name` を含むので、ファイル名に使える
        # 文字へ落とす（`/` や空白は `_`）。
        key=$(printf '%s' "$key" | tr '/ \t:*?"<>|' '___________')
        body=$("$BIN" decompile "$fixture" --addr "$addr" 2>/dev/null)
        [ -n "$body" ] || continue
        # 先頭のヘッダ行（アドレスを含む）は落とす。
        printf '%s\n' "$body" | tail -n +2 > "$out/$name/$key.c"
      done
  count=$((count + 1))
done

echo "dump: $count fixtures -> $out"
