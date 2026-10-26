#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
clang -arch arm64e -c tests/arm64e.s -o tests/fixtures/arm64e.o
# Use the same source for both slices, without host-dependent executable linking.
clang -arch arm64 -O2 -fno-stack-protector -fno-vectorize -fno-slp-vectorize -c tests/cases/c/arith_mixed.c -o tests/fixtures/universal_arm64.o
clang -arch x86_64 -O2 -fno-stack-protector -fno-vectorize -fno-slp-vectorize -c tests/cases/c/arith_mixed.c -o tests/fixtures/universal_x86_64.o
mkdir -p tests/universal
lipo -create tests/fixtures/universal_arm64.o tests/fixtures/universal_x86_64.o -output tests/universal/universal.o
