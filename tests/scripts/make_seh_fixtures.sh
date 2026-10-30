#!/usr/bin/env bash
# Build Windows x64 exception tables without a Windows SDK.
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p target/seh-build
lld-link /lib /machine:x64 /def:tests/cases/pe/seh_imports.def /out:target/seh-build/imports.lib
for opt in O0 O2; do
  for source in seh.c seh_cpp.cpp; do
    name=${source%.*}
    clang --target=x86_64-pc-windows-msvc -"$opt" -fno-inline -c \
      "tests/cases/pe/$source" -o "target/seh-build/$name.$opt.obj"
    lld-link /dll /noentry /nodefaultlib /Brepro /implib:target/seh-build/output.lib \
      /out:"tests/fixtures/$name.$opt.dll" "target/seh-build/$name.$opt.obj" target/seh-build/imports.lib
  done
done
