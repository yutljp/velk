#!/usr/bin/env bash
# 正本（canonical）の実行。x86-64 Linux のコンテナ内で回す。
#
#   docker compose run --rm canonical
#
# 結果は VELK_OUT（既定 tests/out-canonical）に残り、ホストから見える。
# ここで作った疑似 C のダンプが「1番台」で、手元の結果は env-diff で
# 環境差分として比べる。
set -uo pipefail
cd "$(dirname "$0")/.."
export VELK_OUT=${VELK_OUT:-tests/out-canonical}
FIX=$VELK_OUT
mkdir -p "$FIX"

echo "== 正本のツールチェーン =="
for tool in clang ld.lld lld-link llvm-strip llvm-objcopy rustc cargo go; do
  path=$(which "$tool" 2>/dev/null || true)
  if [ -n "$path" ]; then
    case $tool in
      go) version=$("$path" version 2>/dev/null) ;;
      *)  version=$("$path" --version 2>/dev/null | head -1) ;;
    esac
    printf '  %-14s %-40s %s\n' "$tool" "$path" "$version"
  else
    printf '  %-14s (見つからない)\n' "$tool"
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
./tests/dump.sh "$FIX" || status=1

echo
echo "== 正本の結果 =="
tail -1 "$FIX/ladder.txt" 2>/dev/null || true
echo "ダンプ: $FIX/dump (関数ごとの疑似 C)"
exit "$status"
