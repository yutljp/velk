#!/usr/bin/env bash
# Cross-link Mach-O metadata fixtures without an SDK or a system runtime.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p target/chained-build tests/metadata/chained
common=(-O1 -g -fno-inline -ffile-prefix-map="$PWD"=. -fdebug-compilation-dir=. -fvisibility=hidden)
for arch in arm64 x86_64; do
    for source in rtti chained; do
        clang++ --target="$arch-apple-macos13" "${common[@]}" -c "tests/cases/cpp/$source.cpp" -o "target/chained-build/$source.o"
    done
    clang --target="$arch-apple-macos13" "${common[@]}" -fblocks -c tests/objc_metadata.m -o target/chained-build/objc.o
    for mode in chained classic; do
        flag=-fixup_chains
        if [ "$mode" = classic ]; then flag=-no_fixup_chains; fi
        ld64.lld -arch "$arch" -platform_version macos 13.0 13.0 -dylib "$flag" -undefined dynamic_lookup \
            -install_name @rpath/pointers.dylib -oso_prefix "$PWD/" -no_uuid -o "tests/metadata/chained/$arch.$mode.dylib" \
            target/chained-build/rtti.o target/chained-build/chained.o target/chained-build/objc.o
    done
done
