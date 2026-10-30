#!/usr/bin/env bash
# Build only the AArch64 language fixtures, preserving other fixture bytes.
set -euo pipefail
cd "$(dirname "$0")/../.."

ROOT=$(pwd)
OUT=tests/fixtures
mkdir -p "$OUT"

for case in add probe; do
  name=go_probe_arm64; [ "$case" = add ] && name=go_stripped_arm64
  ( cd tests/cases/go && GO111MODULE=off CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
      go build -trimpath -ldflags "-s -w" -o "$ROOT/$OUT/$name" "$case.go" )
done

RUSTC=(rustc "--remap-path-prefix=$ROOT=.")
if command -v aarch64-linux-gnu-gcc >/dev/null; then
  RUSTC+=(--target aarch64-unknown-linux-gnu -C linker=aarch64-linux-gnu-gcc)
elif [ "$(uname -sm)" = "Darwin arm64" ]; then
  RUSTC+=(--target aarch64-apple-darwin)
else
  echo "error: AArch64 Linux linker or native AArch64 macOS required" >&2
  exit 1
fi

"${RUSTC[@]}" -O --crate-name rust_demo -o "$OUT/rust_demo_arm64" tests/cases/rust/add.rs
"${RUSTC[@]}" -O --crate-name rust_probe -o "$OUT/rust_probe_arm64" tests/cases/rust/probe.rs
# Mach-O debug map entries contain absolute paths to standard library objects.
llvm-strip -S "$OUT/rust_demo_arm64" "$OUT/rust_probe_arm64"
llvm-strip -s "$OUT/rust_probe_arm64" -o "$OUT/rust_probe_arm64_stripped"

{
  rustc --version
  go version
  file "$OUT"/*_arm64 "$OUT/rust_probe_arm64_stripped"
} > "$OUT/arm64_lang_toolchain.txt"

if grep -laF -e "$ROOT" -e "$HOME" "$OUT"/*_arm64 "$OUT/rust_probe_arm64_stripped"; then
  echo "error: build paths found in AArch64 language fixtures" >&2
  exit 1
fi
