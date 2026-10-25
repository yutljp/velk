#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
sdk=$(xcrun --sdk macosx --show-sdk-path)
for arch in arm64 x86_64; do
    for level in O0 O2; do
        file="tests/fixtures/objc_${arch}_${level}"
        methods=-Wl,-no_objc_relative_method_lists
        if [ "$level" = O2 ]; then methods=-Wl,-objc_relative_method_lists; fi
        clang -target "$arch-apple-macos11" -isysroot "$sdk" -"$level" -fblocks -fno-objc-msgsend-selector-stubs -fno-objc-msgsend-class-selector-stubs \
            -Wl,-no_fixup_chains -Wl,-no_objc_category_merging "$methods" \
            tests/objc_metadata.m -lobjc -o "$file"
        strip -o "${file}_stripped" "$file"
    done
done
clang --version | head -n 1 > tests/fixtures/objc_toolchain.txt
