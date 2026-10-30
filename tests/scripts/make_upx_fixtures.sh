#!/usr/bin/env bash
set -euo pipefail
out=${1:?output directory required}
mkdir -p "$out"
source_dir=$(cd "$(dirname "$0")/../data" && pwd)
for arch in x86_64 i386 aarch64 arm; do
    case "$arch" in
        x86_64) target=x86_64-linux-gnu;;
        i386) target=i686-linux-gnu;;
        aarch64) target=aarch64-linux-gnu;;
        arm) target=armv7-linux-gnueabi;;
    esac
    clang -target "$target" -c "$source_dir/upx_branch_tail.S" -o "$out/tail.o"
    clang -target "$target" -O1 -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
        -nostdlib -static -fuse-ld=lld -Wl,-e,start -Wl,--build-id=none \
        "$source_dir/upx.c" "$out/tail.o" -o "$out/$arch.elf"
    for method in nrv2b nrv2d nrv2e lzma; do
        UPX= upx -qq --force-overwrite --"$method" -o "$out/$arch.$method.elf" "$out/$arch.elf"
        UPX= upx -qq -d --force-overwrite -o "$out/reference.elf" "$out/$arch.$method.elf"
        cmp "$out/$arch.elf" "$out/reference.elf"
    done
done
rm "$out/reference.elf" "$out/tail.o"
cat > "$out/sample.def" <<'DEF'
LIBRARY sample.dll
EXPORTS
alpha
beta @7 NONAME
DEF
for arch in x86_64 i386; do
    case "$arch" in x86_64) machine=x64; target=x86_64;; i386) machine=x86; target=i686;; esac
    lld-link /lib /def:"$out/sample.def" /machine:"$machine" /out:"$out/sample.lib"
    printf 'LIBRARY helper.dll\nEXPORTS\ncombine\n' > "$out/helper.def"
    lld-link /lib /def:"$out/helper.def" /machine:"$machine" /out:"$out/helper.lib"
    clang -target "$target-pc-windows-msvc" -O1 -fno-stack-protector -fno-builtin \
        -c "$source_dir/upx_pe.c" -o "$out/program.obj"
    lld-link /nodefaultlib /entry:entry /subsystem:console /export:add3 /Brepro \
        /out:"$out/$arch.exe" "$out/program.obj" "$out/sample.lib" "$out/helper.lib"
    for method in nrv2b nrv2d nrv2e lzma; do
        for filter in 0 26 46 49; do
            UPX= upx -qq --force-overwrite --strip-relocs=0 --filter="0x$filter" --"$method" \
                -o "$out/$arch.$method.filter$filter.exe" "$out/$arch.exe"
            UPX= upx -qq -d --force-overwrite -o "$out/reference.exe" "$out/$arch.$method.filter$filter.exe"
            cp "$out/reference.exe" "$out/$arch.reference.exe"
        done
    done
done
rm "$out/helper.def" "$out/helper.lib" "$out/sample.def" "$out/sample.lib" "$out/program.obj" "$out/reference.exe"
for file in "$out/"*.exp "$out/"x86_64.lib "$out/"i386.lib; do
    if [ -f "$file" ]; then rm "$file"; fi
done
