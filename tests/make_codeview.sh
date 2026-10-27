#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p tests/fixtures/codeview
for source in loops structs l4_memory; do
    case "$source" in
        loops) names="count_bits sum_until sum_till_neg sum_until_zero";;
        structs) names="rect_area record_total point_add big_make big_sum word_low_byte flags_level flags_set_mode";;
        l4_memory) names="point_dot array_sum bump banner_first";;
    esac
    set --
    for name in $names; do set -- "$@" "/export:$name"; done
    for level in 0 2; do
        base="tests/fixtures/codeview/$source.O$level"
        clang --target=x86_64-pc-windows-msvc -O"$level" -g -gcodeview -gno-codeview-command-line -ffreestanding -fno-stack-protector -c "tests/cases/c/$source.c" -o "$base.obj" -fdebug-compilation-dir=. -ffile-prefix-map="$PWD"=.
        lld-link /dll /noentry /nodefaultlib /debug /pdbaltpath:"$source.O$level.pdb" /Brepro /out:"$base.dll" /pdb:"$base.pdb" "$base.obj" "$@"
        lld-link /dll /noentry /nodefaultlib /Brepro /out:"$base.stripped.dll" "$base.obj" "$@"
        rm -f "$base.lib" "$base.stripped.lib"
    done
done
# Preserve record lengths while removing machine-specific build directories.
UV_CACHE_DIR=target/uv-cache uv run --no-project python - <<'PY'
from pathlib import Path
prefix = str(Path.cwd()).encode()
replacement = b'build' + b'_' * (len(prefix) - 5)
for path in Path('tests/fixtures/codeview').iterdir():
    if path.suffix in ('.obj', '.pdb'):
        bytes = path.read_bytes().replace(prefix, replacement)
        bytes = bytes.replace(prefix.replace(b'/', b'\\'), replacement)
        path.write_bytes(bytes)
PY
