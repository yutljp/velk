#!/usr/bin/env bash
# Write pseudo-C per function, as input for diffing canonical and local results.
#
#   ./tests/dump.sh tests/out-canonical   # -> tests/out-canonical/dump/<fixture>/<function>.c
#
# The header line, which carries the function's address, is dropped so the
# files compare across environments.
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
  # Take the function list from `functions`; unnamed functions are keyed by address.
  "$BIN" functions "$fixture" --limit 100000 2>/dev/null | tail -n +3 \
    | awk '{print $1"\t"$3}' | while IFS=$'\t' read -r addr symbol; do
        [ -n "$addr" ] || continue
        key=${symbol}
        case "$symbol" in
          "<unnamed>"|"") key=$addr ;;
        esac
        # Go symbols look like `pkg/path.Name`; map characters unsafe in file
        # names (`/`, whitespace, ...) to `_`.
        key=$(printf '%s' "$key" | tr '/ \t:*?"<>|' '___________')
        body=$("$BIN" decompile "$fixture" "$addr" 2>/dev/null)
        [ -n "$body" ] || continue
        # Drop the header line, which contains the address.
        printf '%s\n' "$body" | tail -n +2 > "$out/$name/$key.c"
      done
  count=$((count + 1))
done

echo "dump: $count fixtures -> $out"
