#!/usr/bin/env bash
# Build freestanding control-flow fixtures with no paths or timestamps.
set -euo pipefail
cd "$(dirname "$0")/../.."
for isa in x86_64 aarch64; do
  for opt in O0 O2; do
    for source in flattened flattened_stores predicates; do
      clang --target="$isa-unknown-linux-gnu" -"$opt" -fno-inline \
        -fno-stack-protector -c "tests/cases/control_flow/$source.c" \
        -o "tests/fixtures/${source}_${isa}_${opt}.o"
    done
  done
done
