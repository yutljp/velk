#!/usr/bin/env bash
set -euo pipefail
out=${1:?output directory required}
mkdir -p "$out"
source_dir=$(cd "$(dirname "$0")/../tests/data" && pwd)
for compiler in g++ clang++; do
    if ! command -v "$compiler" >/dev/null; then
        echo "SKIP $compiler: compiler unavailable" >&2
        continue
    fi
    for library in libstdc++ libc++; do
        if [ "$compiler" = g++ ] && [ "$library" = libc++ ]; then continue; fi
        flags=()
        if [ "$compiler" = clang++ ]; then flags+=("-stdlib=$library"); else flags+=(-DEXPECT_GNU); fi
        if ! printf '#include <iostream>\n#if defined(EXPECT_GNU) && !defined(__GLIBCXX__)\n#error libstdc++ required\n#endif\nint main() {}\n' | "$compiler" "${flags[@]}" -x c++ - -o "$out/check" 2>"$out/check.log"; then
            echo "SKIP $compiler $library: standard library unavailable" >&2
            continue
        fi
        abis=(1)
        if [ "$library" = libstdc++ ]; then abis=(0 1); fi
        for abi in "${abis[@]}"; do
            abi_flags=(-D_GLIBCXX_USE_CXX11_ABI="$abi")
            for opt in 0 2; do
                "$compiler" "${flags[@]}" "${abi_flags[@]}" -O"$opt" -g -fno-stack-protector \
                    "$source_dir/cxx_streams.cpp" -o "$out/$compiler-$library-abi$abi-O$opt"
            done
        done
    done
done
if command -v aarch64-linux-gnu-g++ >/dev/null && command -v qemu-aarch64 >/dev/null; then
    for abi in 0 1; do
        for opt in 0 2; do
            aarch64-linux-gnu-g++ -D_GLIBCXX_USE_CXX11_ABI="$abi" -O"$opt" -g -fno-stack-protector \
                "$source_dir/cxx_streams.cpp" -o "$out/aarch64-g++-libstdc++-abi$abi-O$opt"
        done
    done
else
    echo 'SKIP AArch64 C++ programs: cross compiler or native runner unavailable' >&2
fi
if command -v qemu-aarch64 >/dev/null; then
    for library in libstdc++ libc++; do
        if ! printf '#include <iostream>\nint main() {}\n' | clang++ --target=aarch64-linux-gnu \
            -stdlib="$library" -x c++ - -o "$out/check-aarch64" 2>"$out/check-aarch64.log"; then
            echo "SKIP AArch64 clang++ $library: cross standard library unavailable" >&2
            continue
        fi
        for opt in 0 2; do
            clang++ --target=aarch64-linux-gnu -stdlib="$library" -O"$opt" -g -fno-stack-protector \
                "$source_dir/cxx_streams.cpp" -o "$out/aarch64-clang++-$library-abi1-O$opt"
        done
    done
fi
for arch in x86_64 aarch64; do
    for opt in 0 2; do
        clang++ --target="$arch-linux-gnu" -O"$opt" -fPIC -fno-exceptions \
            -fno-stack-protector -c "$source_dir/cxx_stream_abi.cpp" -o "$out/$arch-abi-O$opt.o"
        ld.lld -shared -Bsymbolic "$out/$arch-abi-O$opt.o" -o "$out/$arch-abi-O$opt.so"
    done
done
if command -v ld64.lld >/dev/null; then
    for arch in x86_64 arm64; do
        for opt in 0 2; do
            clang++ --target="$arch-apple-macos13" -O"$opt" -fno-exceptions \
                -fno-stack-protector -c "$source_dir/cxx_stream_abi.cpp" -o "$out/$arch-abi-O$opt.macho.o"
            ld64.lld -dylib -arch "$arch" -platform_version macos 13.0 13.0 \
                -undefined dynamic_lookup "$out/$arch-abi-O$opt.macho.o" -o "$out/$arch-abi-O$opt.dylib"
        done
    done
fi
