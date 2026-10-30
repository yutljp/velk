#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
out=${1:-target/mba-fixtures}
mkdir -p "$out"
for isa in x86_64 aarch64; do
    for optimization in O0 O2; do
        clang --target="$isa-unknown-linux-gnu" -"$optimization" -fno-inline \
            -fno-stack-protector -c tests/cases/mba/expressions.c \
            -o "$out/${isa}_${optimization}.o"
    done
done
