"""Build additional library archives and statically linked measurement programs."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / 'target/library-signatures/extended'
LEVELS = ('O0', 'O1', 'O2', 'O3', 'Os')
TARGETS = {
    'x86_64': ('gcc', [], 'x86_64-linux-gnu', 'linux-x86_64', 'x86_64-unknown-linux-gnu'),
    'aarch64': ('aarch64-linux-gnu-gcc', [], 'aarch64-linux-gnu', 'linux-aarch64', 'aarch64-unknown-linux-gnu'),
    'i386': ('gcc', ['-m32', '-isystem', '/usr/include/' + subprocess.check_output(['gcc', '-dumpmachine'], text=True).strip()], 'i686-linux-gnu', 'linux-x86', 'i686-unknown-linux-gnu'),
    'arm32': ('arm-linux-gnueabihf-gcc', ['-marm'], 'arm-linux-gnueabihf', 'linux-armv4', 'armv7-unknown-linux-gnueabihf'),
}


def run(args, directory, log):
    with log.open('ab') as stream:
        subprocess.run([str(a) for a in args], cwd=directory, stdout=stream,
                       stderr=subprocess.STDOUT, check=True,
                       env={**os.environ, 'SOURCE_DATE_EPOCH': '0', 'PATH': str(OUT / 'tools') + os.pathsep + os.environ['PATH']})


def output(args, directory=ROOT):
    return subprocess.check_output([str(a) for a in args], cwd=directory, text=True).strip()


def pack(path):
    destination = ROOT / 'tests/library_signatures' / (path.name + '.gz')
    destination.write_bytes(gzip.compress(path.read_bytes(), mtime=0))


def signatures(path, stem, accepted=None):
    destination = OUT / (stem + '.json')
    run([ROOT / 'target/release/velk', '--build-signatures', path, '--output', destination], ROOT, OUT / 'signatures.log')
    database = json.loads(destination.read_text())
    for entry in database['entries']:
        entry['set'] = stem
    if accepted is not None:
        database['entries'] = [e for e in database['entries'] if e['name'] in accepted]
    destination.write_text(json.dumps(database, separators=(',', ':')))
    return database['entries']


def text_symbols(path):
    names = set()
    for line in output(['nm', '--defined-only', path]).splitlines():
        columns = line.split()
        if len(columns) >= 3 and columns[-2] in ('t', 'T', 'w', 'W'):
            names.add(columns[-1])
    return names


def save_fixture(executable, names, stem):
    run(['llvm-strip', '--strip-debug', executable], ROOT, OUT / 'strip.log')
    run(['llvm-strip', '--strip-all', executable, '-o', OUT / (stem + '.stripped.elf')], ROOT, OUT / 'strip.log')
    truth = {}
    for line in output(['nm', '-n', '--defined-only', executable]).splitlines():
        columns = line.split()
        if len(columns) == 3 and columns[1] in ('t', 'T', 'w', 'W') and columns[2] in names:
            truth.setdefault(str(int(columns[0], 16) & (~1 if '.arm32.' in stem else -1)), []).append(columns[2])
    if not truth:
        raise RuntimeError(f'no library symbols: {stem}')
    truth_path = OUT / (stem + '.truth.json')
    truth_path.write_text(json.dumps(truth, sort_keys=True, separators=(',', ':')))
    for path in (executable, OUT / (stem + '.stripped.elf'), truth_path):
        pack(path)


def build_c(library, arch, level, source):
    cc, target_flags, host, openssl_target, _ = TARGETS[arch]
    stem = f'{library}.{arch}.{level}'
    directory = OUT / stem
    directory.mkdir(exist_ok=True)
    log = directory / 'build.log'
    flags = [*target_flags, f'-{level}', '-fno-pie', '-funwind-tables',
             f'-ffile-prefix-map={source}={library}', f'-ffile-prefix-map={ROOT}=.']
    if library == 'musl':
        archive = directory / 'lib/libc.a'
        if not archive.exists():
            run([source / 'configure', '--disable-shared', '--disable-wrapper', '--enable-optimize=',
                 f'--target={host}', 'AR=ar', 'RANLIB=ranlib', f'CC={cc}', f'CFLAGS={" ".join(flags)}'], directory, log)
            run(['make', '-j5', 'AR=ar', 'RANLIB=ranlib', 'lib/libc.a', 'obj/crt/crt1.o', 'obj/crt/crti.o', 'obj/crt/crtn.o',
                 f'CFLAGS={" ".join(flags)}'], directory, log)
        archives = [archive]
        includes = ['-nostdinc', '-I', directory / 'obj/include', '-I', source / 'arch' / ('i386' if arch == 'i386' else {'arm32':'arm'}.get(arch, arch)), '-I', source / 'arch/generic', '-I', source / 'include']
        link = ['-nostdlib', directory / 'obj/crt/crt1.o', directory / 'obj/crt/crti.o', '-Wl,--start-group', archive, '-lgcc', '-lgcc_eh', '-Wl,--end-group', directory / 'obj/crt/crtn.o']
    elif library == 'mbedtls':
        archive = directory / 'library/libmbedtls.a'
        if not archive.exists():
            wrapper = OUT / 'uv-python'
            wrapper.write_text('#!/bin/sh\nexec uv run --no-project /usr/bin/python3 "$@"\n')
            wrapper.chmod(0o755)
            run(['cmake', '-S', source, '-B', directory, f'-DCMAKE_C_COMPILER={cc}',
                 f'-DCMAKE_C_FLAGS={" ".join(flags)}', '-DCMAKE_BUILD_TYPE=', '-DCMAKE_SYSTEM_NAME=Linux', '-DCMAKE_POLICY_VERSION_MINIMUM=3.5',
                 '-DENABLE_TESTING=OFF', '-DENABLE_PROGRAMS=OFF', '-DMBEDTLS_FATAL_WARNINGS=OFF',
                 '-DTF_PSA_CRYPTO_FATAL_WARNINGS=OFF', f'-DPython3_EXECUTABLE={wrapper}'], directory, log)
            run(['cmake', '--build', directory, '-j5'], directory, log)
        archives = [archive, directory / 'library/libmbedx509.a', directory / 'tf-psa-crypto/core/libtfpsacrypto.a']
        includes = ['-I', source / 'include', '-I', source / 'tf-psa-crypto/include', '-I', source / 'tf-psa-crypto/drivers/builtin/include']
        link = [*archives, '-lpthread']
    elif library == 'openssl':
        flags = [flag for flag in flags if not flag.startswith('-ffile-prefix-map=')]
        archive = directory / 'libcrypto.a'
        if not archive.exists():
            (directory / 'apps/include').mkdir(parents=True, exist_ok=True)
            run(['perl', source / 'Configure', openssl_target, 'no-shared', 'no-tests', 'no-apps', 'no-asm',
                 'no-module', f'CC={cc}', *flags], directory, log)
            run(['make', '-j5', 'build_libs'], directory, log)
        archives = [archive]
        includes = ['-I', directory / 'include', '-I', source / 'include']
        link = [archive, '-ldl', '-lpthread']
    else:
        archive = directory / 'libsodium.a'
        if not archive.exists():
            include = directory / 'include/sodium'
            include.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / 'builds/msvc/version.h', include / 'version.h')
            defines = ['CONFIGURED', 'DEV_MODE', '_GNU_SOURCE', 'NATIVE_LITTLE_ENDIAN', 'HAVE_STDINT_H',
                       'HAVE_INTTYPES_H', 'HAVE_ATOMIC_OPS', 'HAVE_C11_MEMORY_FENCES', 'HAVE_GCC_MEMORY_FENCES',
                       'HAVE_WEAK_SYMBOLS', 'HAVE_SYS_MMAN_H', 'HAVE_MMAP', 'HAVE_MLOCK', 'HAVE_MADVISE',
                       'HAVE_MPROTECT', 'HAVE_SYSCONF', 'HAVE_GETPID', 'HAVE_NANOSLEEP', 'HAVE_CLOCK_GETTIME',
                       'HAVE_SYS_RANDOM_H', 'HAVE_SYS_AUXV_H', 'HAVE_POSIX_MEMALIGN', 'HAVE_PTHREAD']
            objects = []
            commands = []
            for index, path in enumerate(sorted((source / 'src/libsodium').rglob('*.c'))):
                obj = directory / f'{index}.o'
                objects.append(obj)
                commands.append([cc, *flags, '-fvisibility=hidden', '-fno-strict-aliasing', '-fwrapv',
                                 *[f'-D{d}=1' for d in defines], '-DTLS=_Thread_local', '-I', directory / 'include', '-I', directory / 'include/sodium',
                                 '-I', source / 'src/libsodium/include', '-I', source / 'src/libsodium/include/sodium',
                                 '-c', path, '-o', obj])
            with ThreadPoolExecutor(max_workers=5) as pool:
                list(pool.map(lambda command: run(command, directory, log), commands))
            run(['ar', 'rcsD', archive, *objects], directory, log)
        archives = [archive]
        includes = ['-I', directory / 'include', '-I', source / 'src/libsodium/include', '-I', source / 'src/libsodium/include/sodium']
        link = [archive, '-lpthread']
    names = set()
    entries = []
    for index, archive in enumerate(archives):
        names.update(text_symbols(archive))
        entries.extend(signatures(archive, f'{stem}.{index}'))
    executable = OUT / (stem + '.elf')
    run([cc, *flags, '-static', '-no-pie', '-Wl,--build-id=none', *includes,
         ROOT / f'signatures/programs/{library}.c', *link, '-o', executable], directory, log)
    save_fixture(executable, names, stem)
    return entries


def build_rust(arch, level):
    cc, flags, _, _, target = TARGETS[arch]
    stem = f'rust.{arch}.{level}'
    executable = OUT / (stem + '.elf')
    linker = OUT / ('link-' + arch)
    linker.write_text(f'#!/bin/sh\nexec {cc} {" ".join(flags)} "$@"\n')
    linker.chmod(0o755)
    rust_sources = Path(output(['rustc', '--print', 'sysroot'])) / 'lib/rustlib/src/rust'
    run(['rustc', ROOT / 'signatures/programs/rust.rs', '--edition=2024', '--target', target,
         '--remap-path-prefix', f'{ROOT}=.', '--remap-path-prefix', f'{rust_sources}=rust', '-C', f'opt-level={level[1:]}', '-C', f'linker={linker}', '-C', 'target-feature=+crt-static',
         '-C', 'relocation-model=static', '-C', 'force-unwind-tables=yes', '-C', 'link-arg=-Wl,--build-id=none',
         '-o', executable], ROOT, OUT / 'rust.log')
    names = {name for name in text_symbols(executable) if name.startswith(('_R', '_ZN'))}
    listing = json.loads(output([ROOT / 'target/release/velk', '-f', executable, '--json', '--no-default-signatures', '--limit', '100000']))
    rust_addresses = set()
    for line in output(['nm', '-n', '--defined-only', executable]).splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] in names:
            rust_addresses.add(int(fields[0], 16) & (~1 if arch == 'arm32' else -1))
    demangled = set()
    for function in listing['functions']:
        name = function.get('name')
        if int(function['addr'], 16) not in rust_addresses or not name:
            continue
        plain = name.startswith(('std::', 'core::', 'alloc::')) and '<' not in name
        concrete_trait = name.startswith(('<std::', '<core::', '<alloc::')) \
            and name.count('<') == 1 and name.count('>') == 1 and ' as ' in name
        if (plain or concrete_trait) and '{closure' not in name:
            demangled.add(name)
    # Rust executables include the target's libc; only Rust symbols belong to this set.
    entries = signatures(executable, stem, demangled)
    save_fixture(executable, names, stem)
    return entries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sources', type=Path, help='directory containing the four pinned source clones')
    parser.add_argument('--library', choices=['musl', 'mbedtls', 'libsodium', 'openssl', 'rust'])
    parser.add_argument('--arch', choices=TARGETS)
    parser.add_argument('--level', choices=LEVELS)
    parser.add_argument('--refresh-signatures', action='store_true', help='rebuild entries using cached library archives')
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'tools').mkdir(exist_ok=True)
    for name in ('python', 'python3'):
        wrapper = OUT / 'tools' / name
        wrapper.write_text('#!/bin/sh\nexec uv run --no-project /usr/bin/python3 \"$@\"\n')
        wrapper.chmod(0o755)
    manifest_path = ROOT / 'signatures/extended-sources.json'
    manifest = json.loads(manifest_path.read_text())
    for name, expected in manifest['reference_sources'].items():
        path = ROOT / 'signatures/sources' / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit(f'wrong reference source checksum: {name}')
    for tool, expected in manifest['compilers'].items():
        actual = next(line for line in output([tool, '--version']).splitlines() if line.strip())
        if actual != expected:
            raise SystemExit(f'wrong tool version: {tool}: {actual}')
    if output(['uv', 'run', '--no-project', '/usr/bin/python3', '--version']) != manifest['python']['interpreter']:
        raise SystemExit('wrong Python interpreter version')
    if output(['uv', 'run', '--no-project', '/usr/bin/python3', '-c', 'import jinja2; print(jinja2.__version__)']) != manifest['python']['jinja2']:
        raise SystemExit('wrong Jinja2 version')
    if output(['rustc', '-Vv']) != manifest['rust']:
        raise SystemExit('wrong Rust compiler version')
    for target, libraries in manifest['rust_targets'].items():
        directory = Path(output(['rustc', '--print', 'target-libdir', '--target', target]))
        for name, expected in libraries.items():
            if hashlib.sha256((directory / name).read_bytes()).hexdigest() != expected:
                raise SystemExit(f'wrong Rust target library: {target}/{name}')
    for library, record in manifest['libraries'].items():
        source = args.sources.resolve() / library
        if output(['git', 'rev-parse', 'HEAD'], source) != record['commit']:
            raise SystemExit(f'wrong source commit: {library}')
        if output(['git', 'status', '--porcelain', '--untracked-files=no'], source):
            raise SystemExit(f'modified source files: {library}')
        for relative, commit in record.get('submodules', {}).items():
            if output(['git', 'rev-parse', 'HEAD'], source / relative) != commit:
                raise SystemExit(f'wrong submodule commit: {library}/{relative}')
    mbedtls = args.sources.resolve() / 'mbedtls'
    local_mbedtls = OUT / 'mbedtls-source'
    if not local_mbedtls.exists():
        shutil.copytree(mbedtls, local_mbedtls, ignore=shutil.ignore_patterns('.git', '.env*', '*.pem', 'id_rsa', 'credentials.*', 'secrets.*', 'idapro.hexlic'))
        shutil.copytree(local_mbedtls / 'framework', local_mbedtls / 'tf-psa-crypto/framework', dirs_exist_ok=True)
    local_openssl = OUT / 'openssl-source'
    if not local_openssl.exists():
        shutil.copytree(args.sources.resolve() / 'openssl', local_openssl, ignore=shutil.ignore_patterns('.git', '.env*', '*.pem', 'id_rsa', 'credentials.*', 'secrets.*', 'idapro.hexlic'))
    import notices
    notices.write(args.sources.resolve())
    for arch in ([args.arch] if args.arch else TARGETS):
        for level in ([args.level] if args.level else LEVELS):
            for library in ([args.library] if args.library else ['musl', 'mbedtls', 'libsodium', 'openssl', 'rust']):
                stem = f'{library}.{arch}.{level}'
                cache = OUT / (stem + '.entries.json')
                if args.refresh_signatures or not cache.exists():
                    print(f'Building {stem}', flush=True)
                    entries = build_rust(arch, level) if library == 'rust' else build_c(library, arch, level, local_mbedtls if library == 'mbedtls' else local_openssl if library == 'openssl' else args.sources.resolve() / library)
                    cache.write_text(json.dumps(entries, separators=(',', ':')))
                print(f'{stem}: {len(json.loads(cache.read_text()))} signatures', flush=True)
    import pack
    pack.main()


if __name__ == '__main__':
    main()
