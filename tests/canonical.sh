#!/usr/bin/env bash
# Canonical run, inside the x86-64 Linux container.
#
#   docker compose run --rm canonical
#
# Results go to VELK_OUT (default tests/out-canonical), visible from the host.
# The pseudo-C dump produced here is the reference; compare local results
# against it with env-diff.sh.
set -uo pipefail
cd "$(dirname "$0")/.."
export VELK_OUT=${VELK_OUT:-tests/out-canonical}
FIX=$VELK_OUT
mkdir -p "$FIX"

echo "== canonical toolchain =="
for tool in clang ld.lld lld-link llvm-strip llvm-objcopy rustc cargo go; do
  path=$(which "$tool" 2>/dev/null || true)
  if [ -n "$path" ]; then
    case $tool in
      go) version=$("$path" version 2>/dev/null) ;;
      *)  version=$("$path" --version 2>/dev/null | head -1) ;;
    esac
    printf '  %-14s %-40s %s\n' "$tool" "$path" "$version"
  else
    printf '  %-14s (not found)\n' "$tool"
  fi
done
{
  echo "uname: $(uname -srm)"
  for tool in clang ld.lld lld-link llvm-strip llvm-objcopy rustc cargo go; do
    path=$(which "$tool" 2>/dev/null || true)
    [ -n "$path" ] || continue
    case $tool in
      go) version=$("$path" version 2>/dev/null) ;;
      *)  version=$("$path" --version 2>/dev/null | head -1) ;;
    esac
    printf '%s: %s (%s)\n' "$tool" "$path" "$version"
  done
} > "$FIX/toolchain.txt"

status=0
./tests/make_fixtures.sh || status=1
./tests/smoke.sh || status=1
./tests/ladder.sh | tee "$FIX/ladder.txt" || status=1
# The dump decompiles every function, which is slow; it is only needed for diffs.
if [ "${VELK_DUMP:-1}" = 1 ]; then
  ./tests/dump.sh "$FIX" || status=1
else
  echo "dump: skipped (VELK_DUMP=0)"
fi

echo
echo "== canonical results =="
tail -1 "$FIX/ladder.txt" 2>/dev/null || true
echo "dump: $FIX/dump (pseudo-C per function)"
exit "$status"
