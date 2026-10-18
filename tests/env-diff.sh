#!/usr/bin/env bash
# 正本（tests/out-canonical）と手元（tests/out）の環境差分を出す。
#
#   ./tests/env-diff.sh              # 差分の要約
#   ./tests/env-diff.sh --show 3     # 先頭 3 件の差分本文も表示
#
# 期待する読み方:
#   - dump が一致      -> 環境が変わっても同じ疑似 C が出ている
#   - 片方にしか無い   -> その関数が片方で復元できていない（＝実装の穴）
#   - 本文が違う       -> コンパイラ/版による codegen の差
set -uo pipefail
cd "$(dirname "$0")/.."

CANON=tests/out-canonical
LOCAL=${VELK_OUT:-tests/out}
SHOW=0
[ "${1:-}" = "--show" ] && SHOW=${2:-3}

[ -d "$CANON/dump" ] || { echo "正本のダンプが無い: $CANON/dump" >&2; echo "先に docker compose run --rm canonical" >&2; exit 2; }
[ -d "$LOCAL/dump" ] || { echo "手元のダンプが無い: $LOCAL/dump" >&2; echo "先に VELK_OUT=$LOCAL ./tests/dump.sh $LOCAL" >&2; exit 2; }

echo "== 環境 =="
printf '  正本: %s\n' "$(head -1 "$CANON/toolchain.txt" 2>/dev/null || echo unknown)"
printf '  手元: %s\n' "$(head -1 "$LOCAL/toolchain.txt" 2>/dev/null || echo unknown)"
echo

# 一致・欠落・不一致を数える。
same=0; differ=0; only_canon=0; only_local=0
diff_list=$(mktemp); miss_list=$(mktemp); per=$(mktemp)
trap 'rm -f "$diff_list" "$miss_list" "$per"' EXIT

while IFS= read -r rel; do
  case "$rel" in */.DS_Store) continue ;; esac
  fixture=${rel%%/*}
  if [ ! -f "$LOCAL/dump/$rel" ]; then
    only_canon=$((only_canon + 1)); printf '  %s\n' "$rel" >> "$miss_list"
    printf '%s\tonly_canon\n' "$fixture" >> "$per"; continue
  fi
  if cmp -s "$CANON/dump/$rel" "$LOCAL/dump/$rel"; then
    same=$((same + 1)); printf '%s\tsame\n' "$fixture" >> "$per"
  else
    differ=$((differ + 1)); printf '  %s\n' "$rel" >> "$diff_list"
    printf '%s\tdiffer\n' "$fixture" >> "$per"
  fi
done < <(cd "$CANON/dump" && find . -name '*.c' | sed 's|^\./||' | sort)

while IFS= read -r rel; do
  case "$rel" in */.DS_Store) continue ;; esac
  if [ ! -f "$CANON/dump/$rel" ]; then
    only_local=$((only_local + 1)); printf '%s\tonly_local\n' "${rel%%/*}" >> "$per"
  fi
done < <(cd "$LOCAL/dump" && find . -name '*.c' | sed 's|^\./||' | sort)

total=$((same + differ + only_canon + only_local))
printf '関数ごとの比較: %d 件\n' "$total"
printf '  一致      %d\n' "$same"
printf '  本文が違う %d\n' "$differ"
printf '  正本のみ  %d\n' "$only_canon"
printf '  手元のみ  %d\n' "$only_local"

echo
echo "== フィクスチャごと（差の多い順） =="
awk -F'\t' '{ t[$1]++; if ($2=="same") s[$1]++; if ($2=="differ") d[$1]++; if ($2=="only_canon") c[$1]++; if ($2=="only_local") l[$1]++ }
  END { for (f in t) printf "%s\t%d\t%d\t%d\t%d\t%d\n", f, t[f], s[f]+0, d[f]+0, c[f]+0, l[f]+0 }' "$per" \
  | sort -t'	' -k4,4nr -k6,6nr | head -15 \
  | awk -F'\t' '{ printf "  %-28s 計 %4d  一致 %4d  不一致 %4d  正本のみ %3d  手元のみ %3d\n", $1, $2, $3, $4, $5, $6 }'

if [ -s "$diff_list" ]; then
  echo
  echo "== 本文が違う（先頭 20 件） =="
  head -20 "$diff_list"
  if [ "$SHOW" -gt 0 ]; then
    head -"$SHOW" "$diff_list" | while read -r rel; do
      echo
      echo "--- $rel"
      diff -u "$CANON/dump/$rel" "$LOCAL/dump/$rel" | sed -n '1,40p'
    done
  fi
fi

if [ -s "$miss_list" ]; then
  echo
  echo "== 正本にしか無い（手元で復元できていない） =="
  head -20 "$miss_list"
fi

# 本文の不一致は環境差分であって失敗ではない。復元漏れ（片側にしか無い
# 関数）だけを終了コードで知らせる。
[ "$only_canon" -eq 0 ] && [ "$only_local" -eq 0 ]
