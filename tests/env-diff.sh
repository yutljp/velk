#!/usr/bin/env bash
# Show environment differences between canonical (tests/out-canonical) and local (tests/out) results.
#
#   ./tests/env-diff.sh              # summary
#   ./tests/env-diff.sh --show 3     # also print the first 3 diffs
#
# How to read the result:
#   - same            -> the same pseudo-C across environments
#   - only on one side -> the function was not recovered on the other side (a gap in the implementation)
#   - body differs    -> codegen difference from the compiler or its version
set -uo pipefail
cd "$(dirname "$0")/.."

CANON=tests/out-canonical
LOCAL=${VELK_OUT:-tests/out}
SHOW=0
[ "${1:-}" = "--show" ] && SHOW=${2:-3}

[ -d "$CANON/dump" ] || { echo "no canonical dump: $CANON/dump" >&2; echo "run first: docker compose run --rm canonical" >&2; exit 2; }
[ -d "$LOCAL/dump" ] || { echo "no local dump: $LOCAL/dump" >&2; echo "run first: VELK_OUT=$LOCAL ./tests/dump.sh $LOCAL" >&2; exit 2; }

echo "== environments =="
printf '  canonical: %s\n' "$(head -1 "$CANON/toolchain.txt" 2>/dev/null || echo unknown)"
printf '  local:     %s\n' "$(head -1 "$LOCAL/toolchain.txt" 2>/dev/null || echo unknown)"
echo

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
printf 'functions compared: %d\n' "$total"
printf '  same            %d\n' "$same"
printf '  body differs    %d\n' "$differ"
printf '  canonical only  %d\n' "$only_canon"
printf '  local only      %d\n' "$only_local"

echo
echo "== per fixture (most differences first) =="
awk -F'\t' '{ t[$1]++; if ($2=="same") s[$1]++; if ($2=="differ") d[$1]++; if ($2=="only_canon") c[$1]++; if ($2=="only_local") l[$1]++ }
  END { for (f in t) printf "%s\t%d\t%d\t%d\t%d\t%d\n", f, t[f], s[f]+0, d[f]+0, c[f]+0, l[f]+0 }' "$per" \
  | sort -t'	' -k4,4nr -k6,6nr | head -15 \
  | awk -F'\t' '{ printf "  %-28s total %4d  same %4d  differ %4d  canonical only %3d  local only %3d\n", $1, $2, $3, $4, $5, $6 }'

if [ -s "$diff_list" ]; then
  echo
  echo "== body differs (first 20) =="
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
  echo "== canonical only (not recovered locally) =="
  head -20 "$miss_list"
fi

# A differing body is an environment difference, not a failure. Only missing
# functions (present on one side only) affect the exit code.
[ "$only_canon" -eq 0 ] && [ "$only_local" -eq 0 ]
