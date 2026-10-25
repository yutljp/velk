#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
sdk=$(xcrun --sdk macosx --show-sdk-path)
for arch in arm64 x86_64; do
    clang -target "$arch-apple-macos11" -isysroot "$sdk" -O1 \
        tests/cases/c/type_library.c -o "tests/fixtures/type_library_${arch}"
done
