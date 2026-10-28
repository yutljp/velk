"""Build and inspect a bounded corpus.

Build velk with `CARGO_BUILD_JOBS=2 CARGO_PROFILE_RELEASE_INCREMENTAL=true
cargo build --release`. Run `UV_CACHE_DIR=target/uv-cache uv run tools/census_build.py`, followed by
`UV_CACHE_DIR=target/uv-cache uv run tools/census.py`. Results, including
attempted commands and per-binary diagnostics, are under target/census.
Use --resume only when corpus sources and toolchains have not changed.
"""
import argparse
import collections
import concurrent.futures
import hashlib
import itertools
import json
import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / 'target/census'
BIN = ROOT / 'target/release/velk'
os.environ.setdefault('RAYON_NUM_THREADS', '1')
os.environ.setdefault('VELK_THREADS', '1')
PROCESSES = set()
PROCESS_LOCK = threading.Lock()
STOP = threading.Event()


def run(command, timeout=30):
    with PROCESS_LOCK:
        if STOP.is_set():
            raise InterruptedError('census interrupted')
        process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, errors='replace')
        PROCESSES.add(process)
    try:
        try:
            output, error = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            return None, '', 'timeout'
        return process.returncode, output, error
    finally:
        with PROCESS_LOCK:
            PROCESSES.discard(process)


def cancel(jobs):
    STOP.set()
    for job in jobs:
        job.cancel()
    with PROCESS_LOCK:
        for process in tuple(PROCESSES):
            try:
                process.terminate()
            except ProcessLookupError:
                pass


def error_text(code, error):
    return error.strip() or ('timeout' if code is None else f'exit {code}')


def system_binaries():
    seen = set()
    for directory in ('/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/libexec'):
        iterator = Path(directory).rglob('*') if directory == '/usr/libexec' else Path(directory).glob('*')
        for path in sorted(iterator):
            try:
                real = path.resolve(strict=True)
                if real in seen or not real.is_file():
                    continue
                with real.open('rb') as stream:
                    magic = stream.read(4)
            except OSError:
                continue
            if magic not in (b'\x7fELF', b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe',
                             b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'):
                continue
            seen.add(real)
            yield {'name': 'system:' + str(path), 'path': str(path), 'kind': 'system'}


def verify(entry):
    path = Path(entry['path'])
    code, output, error = run(['llvm-readobj', '--file-headers', '--needed-libs', str(path)])
    if code != 0:
        return {'error': error_text(code, error)}
    pie = 'MH_PIE' in output or bool(re.search(r'Type:.*(?:ET_DYN|SharedObject)', output))
    libraries = re.findall(r'^\s+([^\s\[\]]+\.(?:so(?:\.\d+)*|dylib))\s*$', output, re.M)
    symbols_path = path
    if entry['kind'] in ('crackme', 'symbolic') and path.parent.name == 'cross':
        symbols_path = path.with_name(path.name.rsplit('-', 1)[0] + '.o')
        if entry['kind'] == 'symbolic':
            symbols_path = path.with_name(path.name.rsplit('-', 1)[0] + '-0.o')
    code, symbols, error = run(['llvm-nm', '--undefined-only', str(symbols_path)])
    protector = '__stack_chk_fail' in symbols if code == 0 else None
    disasm_code, disasm, _ = run(['llvm-objdump', '--disassemble', str(path)])
    code_hash = None
    if disasm_code == 0:
        lines = [line for line in disasm.splitlines() if 'file format' not in line]
        code_hash = hashlib.sha256('\n'.join(lines).encode()).hexdigest()
    return {'pie': pie, 'needed_libraries': libraries, 'stack_protector_reference': protector,
            'symbol_error': error_text(code, error) if code != 0 else None,
            'disassembly_sha256': code_hash}


def inspect(entry):
    path = Path(entry['path'])
    name = entry['name']
    record = {'binary': name, 'path': str(path), 'kind': entry['kind'], 'findings': []}
    findings = record['findings']
    if entry['kind'] != 'system':
        record['properties'] = verify(entry)
    code, output, error = run([str(BIN), '-f', '--json', '--limit', '1000000',
                               '--cache', 'off', str(path)], 45)
    try:
        listing = json.loads(output) if code == 0 else {}
        functions = listing.get('functions', [])
    except (ValueError, KeyError):
        listing = {}
        functions = []
    record['functions'] = len(functions)
    record['discovered_functions'] = listing.get('functionCount')
    if record['discovered_functions'] is not None and record['discovered_functions'] > len(functions):
        findings.append('function listing: result limit')
    if not functions:
        findings.append('function listing: ' + (error.strip() or 'no functions'))
    def inspect_c(c):
        for marker in re.findall(r'unsupported:[^\n*]*', c):
            findings.append('unsupported: ' + marker[len('unsupported:'):].strip())
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', dir=OUT, encoding='utf-8') as cfile:
            cfile.write(c)
            cfile.flush()
            syntax_code, _, syntax_error = run(['clang', '-fsyntax-only', '-ferror-limit=0', '-x', 'c', cfile.name], 30)
        if syntax_code != 0:
            errors = re.findall(r'error: (.*)', syntax_error)
            for item in errors or [syntax_error.strip() or 'timeout']:
                findings.append('syntax: ' + item)
    code, c, error = run([str(BIN), '-D', '--cache', 'off', str(path)], 120)
    if code == 0:
        record['function_attempts'] = len(functions)
        inspect_c(c)
    else:
        findings.append('decompile all: ' + error_text(code, error))
        record['function_attempts'] = 0
        deadline = time.monotonic() + 120
        for function in functions:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                findings.append('decompile: per-function time limit')
                break
            address = function.get('addr')
            if not address:
                findings.append('decompile: missing function address')
                continue
            function_code, function_c, function_error = run(
                [str(BIN), '-D', '--cache', 'off', str(path), address], min(15, remaining))
            record['function_attempts'] += 1
            if function_code != 0:
                findings.append('decompile function: ' + error_text(function_code, function_error))
            if function_c:
                inspect_c(function_c)
    options = {'stdin': {'text': 'test'}, 'timeLimitMs': 1000}
    if '-argv-' in name:
        options['argv'] = ['census', 'test']
    code, output, error = run([str(BIN), '--emulate', '--json', '--cache', 'off',
                               '--emulation-options', json.dumps(options), str(path), 'main'], 15)
    try:
        report = json.loads(output)
        findings.append('emulation: ' + str(report.get('reason')) +
                        (': ' + str(report['error']) if report.get('error') else ''))
    except ValueError:
        findings.append('emulation: ' + error_text(code, error))
    success = next((f for f in functions if (f.get('name') or '').lstrip('_') == 'success'), None)
    main = next((f for f in functions if (f.get('name') or '').lstrip('_') == 'main'), None)
    if success and main and entry['kind'] in ('crackme', 'symbolic'):
        options = {'argv': [1, 4]} if '-argv-' in name else {'stdin': 4}
        code, output, error = run([str(BIN), '--explore', 'main', '--find', success['addr'],
                                   '--symbolic-options', json.dumps(options), '--json',
                                   '--cache', 'off', str(path)], 15)
        try:
            report = json.loads(output)
            findings.append('explore: ' + str(report.get('reason')))
            for diagnostic in report.get('diagnostics', []):
                findings.append('explore diagnostic: ' + str(diagnostic))
        except ValueError:
            findings.append('explore: ' + error_text(code, error))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--resume', action='store_true', help='resume saved results for the same binary')
    parser.add_argument('--workers', type=int, default=4, help='concurrent binary scans (default: 4)')
    args = parser.parse_args()
    if args.workers < 1:
        parser.error('--workers must be a positive integer')
    results_path = OUT / 'results-current.json'
    identity = hashlib.sha256(BIN.read_bytes()).hexdigest()
    results = []
    if args.resume:
        if not results_path.exists():
            parser.error('--resume requires an existing results file')
        saved = json.loads(results_path.read_text())
        if saved.get('velk_sha256') != identity:
            parser.error('--resume requires the same velk binary as the saved results')
        results = [record for record in saved['results']
                   if not any(finding.startswith('census error:')
                              for finding in record['findings'])]
    OUT.mkdir(parents=True, exist_ok=True)
    corpus = OUT / 'native'
    corpus.mkdir(exist_ok=True)
    sources = sorted((ROOT / 'tests/data/crackmes').glob('*.c'))
    sources += [ROOT / 'tests/data/symbolic_native.c']
    compilers = [('native', ['clang'])]
    if sys.platform == 'darwin':
        other_arch = 'x86_64' if platform.machine() in ('arm64', 'aarch64') else 'arm64'
        compilers.append(('native_' + other_arch, ['clang', '-arch', other_arch]))
    for arch, compiler in [('x86_64', 'x86_64-linux-gnu-gcc'),
                           ('aarch64', 'aarch64-linux-gnu-gcc'),
                           ('i386', 'i686-linux-gnu-gcc'),
                           ('arm32', 'arm-linux-gnueabihf-gcc'),
                           ('windows_x86_64', 'x86_64-w64-mingw32-gcc'),
                           ('windows_i386', 'i686-w64-mingw32-gcc')]:
        if shutil.which(compiler):
            compilers.append((arch, [compiler]))
    builds = []
    paths = []
    previous_builds = {}
    builds_path = OUT / 'builds-current.json'
    if args.resume and builds_path.exists():
        previous_builds = {item['name']: item for item in json.loads(builds_path.read_text())}
    def build(item):
        (arch, compiler), source, opt, protector, pie, linkage = item
        name = f'{arch}-{source.stem}-O{opt}-ssp-{protector}-pie-{pie}-{linkage}'
        path = corpus / name
        flags = ['-O' + opt, '-g', '-fno-builtin',
                 '-fstack-protector-all' if protector == 'on' else '-fno-stack-protector',
                 '-fPIE' if pie == 'on' else '-fno-pie', '-pie' if pie == 'on' else '-no-pie']
        if linkage == 'static':
            flags.append('-static')
        inputs = [str(source)]
        if source.stem == 'symbolic_native':
            inputs += [str(ROOT / 'tests/data/symbolic_libc.c')]
            if sys.platform == 'darwin':
                flags.append('-Dstdin=__stdinp')
        command = [*compiler, *flags, *inputs, '-o', str(path)]
        previous = previous_builds.get(name)
        if previous and previous['command'] == command and (previous['status'] != 0 or path.exists()):
            build_result = previous
            code = previous['status']
        else:
            code, _, error = run(command, 60)
            build_result = {'name': name, 'command': command, 'status': code, 'error': error}
        if code == 0:
            return build_result, {'name': name, 'path': str(path),
                                  'kind': 'symbolic' if source.stem == 'symbolic_native' else 'crackme'}
        return build_result, None
    items = itertools.product(compilers, sources, ['0', '2', 's'],
                              ['on', 'off'], ['on', 'off'], ['dynamic', 'static'])
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        jobs = [pool.submit(build, item) for item in items]
        try:
            for job in jobs:
                build_result, entry = job.result()
                builds.append(build_result)
                if entry:
                    paths.append(entry)
        except KeyboardInterrupt:
            cancel(jobs)
            raise
    builds_path.write_text(json.dumps(builds, indent=2))
    manifest = OUT / 'cross-manifest.json'
    if manifest.exists():
        paths.extend(json.loads(manifest.read_text()))
    paths.extend(system_binaries())
    completed = {record['binary'] for record in results}
    pending = [entry for entry in paths if entry['name'] not in completed]
    def save_results():
        temporary = results_path.with_suffix('.tmp')
        temporary.write_text(json.dumps({'velk_sha256': identity, 'results': results}, indent=2))
        temporary.replace(results_path)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        jobs = {pool.submit(inspect, entry): entry for entry in pending}
        try:
            for future in concurrent.futures.as_completed(jobs):
                entry = jobs[future]
                try:
                    record = future.result()
                except (OSError, ValueError) as error:
                    record = {'binary': entry['name'], 'path': entry['path'], 'kind': entry['kind'],
                              'functions': 0, 'function_attempts': 0,
                              'findings': ['census error: ' + str(error)]}
                results.append(record)
                if len(results) % 10 == 0:
                    save_results()
                if len(results) % 100 == 0:
                    write_report(results, builds, identity, len(paths))
                print(f'{len(results)}/{len(paths)} {record["binary"]}', flush=True)
        except KeyboardInterrupt:
            cancel(jobs)
            save_results()
            raise
    save_results()
    write_report(results, builds, identity, len(paths))


def write_report(results, builds, identity, planned=None):
    groups = collections.defaultdict(lambda: collections.Counter())
    blocked = collections.defaultdict(set)
    examples = {}
    example_sizes = {}
    outcomes = collections.Counter()
    for record in results:
        try:
            size = Path(record['path']).stat().st_size
        except OSError:
            size = float('inf')
        for finding, count in collections.Counter(record['findings']).items():
            if finding in ('emulation: return', 'explore: found'):
                outcomes[finding] += 1
                continue
            kind = re.sub(r'0x[0-9a-fA-F]+', '<address>', finding)
            groups[kind][record['binary']] += count
            if not (finding.startswith('explore diagnostic:') and 'explore: found' in record['findings']):
                blocked[kind].add(record['binary'])
            if kind not in examples or size < example_sizes[kind]:
                examples[kind] = record['path']
                example_sizes[kind] = size
    cross_path = OUT / 'cross-builds.json'
    cross_builds = json.loads(cross_path.read_text()) if cross_path.exists() else []
    system_count = sum(record['kind'] == 'system' for record in results)
    revision_code, revision, _ = run(['git', 'rev-parse', 'HEAD'])
    revision = revision.strip() if revision_code == 0 else 'unavailable'
    property_counts = collections.Counter()
    mismatches = collections.defaultdict(list)
    optimization_groups = collections.defaultdict(dict)
    for record in results:
        if 'properties' not in record or '-ssp-' not in record['binary']:
            continue
        properties = record['properties']
        name = record['binary']
        match = re.search(r'-O(0|2|s)-', name)
        if match and properties.get('disassembly_sha256'):
            key = name[:match.start()] + '-O-' + name[match.end():]
            optimization_groups[key][match.group(1)] = properties['disassembly_sha256']
        for label, requested, observed in (
                ('PIE', '-pie-on-' in name, properties.get('pie')),
                ('stack protector', '-ssp-on-' in name, properties.get('stack_protector_reference')),
                ('dynamic linkage', name.endswith('-dynamic'),
                 bool(properties['needed_libraries']) if 'needed_libraries' in properties else None)):
            if observed is None:
                property_counts[label + ': unavailable'] += 1
                mismatches[label + ': unavailable'].append(name)
            elif requested == observed:
                property_counts[label + ': matches request'] += 1
            else:
                property_counts[label + ': differs from request'] += 1
                mismatches[label + ': differs from request'].append(name)
    lines = ['# Census', '', f'Binaries: {len(results)} ({system_count} system).',
             *([f'Incomplete run: {len(results)} of {planned} binaries measured.']
               if planned is not None and len(results) < planned else []),
             f'Native build attempts: {len(builds)}; successful: {sum(b["status"] == 0 for b in builds)}.',
             f'Cross build attempts: {len(cross_builds)}; successful: {sum(b["status"] == 0 for b in cross_builds)}.',
             f'Source revision at reporting: `{revision}`.',
             f'velk SHA-256: `{identity}`.',
             'Commands and failures: `builds-current.json` and `cross-builds.json`. Detailed results and verified executable properties: `results-current.json`.',
             'Cross binaries are freestanding and use the repository input stubs; they are not native libc builds.',
             'System binaries are sampled from /bin, /sbin, /usr/bin, /usr/sbin and /usr/libexec, deduplicated by resolved path. Universal binaries use the default architecture.',
             'PIE is checked from the executable header, linkage from needed-library entries, and stack protection from undefined guard-failure references in the compiled source object or native executable. These checks do not verify optimization level.',
             'Whole-binary decompilation is bounded to 120 seconds. On failure, functions are attempted individually with a 120-second overall budget and 15 seconds per function; the attempted count is recorded. Emulation and exploration are bounded to 15 seconds each. A timeout is a measurement limit.',
             'Ranked by affected binaries; diagnostics from successful searches are counted as observed but not as blocking. Reasons and diagnostics may refer to the same stopped path. Examples are the smallest observed binaries by file size.',
             f'Successful emulation returns: {outcomes["emulation: return"]}; successful explorations: {outcomes["explore: found"]}.',
             f'Binaries with an incomplete per-function attempt: {sum(record.get("function_attempts", 0) < record["functions"] for record in results)}.', '',
             '## Build properties', '',
             f'- Optimization groups with all three variants: {sum(len(group) == 3 for group in optimization_groups.values())}; groups with three distinct disassembly hashes: {sum(len(group) == 3 and len(set(group.values())) == 3 for group in optimization_groups.values())}. Different disassemblies show an observable difference, not a proof of optimization level.',
             *[f'- {key}: {value}' for key, value in sorted(property_counts.items())],
             *[f'- {key}: ' + ', '.join(f'`{name}`' for name in names) for key, names in sorted(mismatches.items())], '',
             '## Findings', '',
             '| Finding | Binaries blocked | Binaries observed | Occurrences | Example |', '|---|---:|---:|---:|---|']
    order = sorted(groups.items(), key=lambda item: (-len(blocked[item[0]]), item[0]))
    for finding, binaries in order:
        example = examples[finding]
        safe = finding.replace('|', '\\|').replace('\n', ' ')
        lines.append(f'| {safe} | {len(blocked[finding])} | {len(binaries)} | {sum(binaries.values())} | `{example}` |')
    for finding, binaries in order:
        lines += ['', '## ' + finding.replace('\n', ' '), '', *[f'- `{name}`: {count}' for name, count in binaries.items()]]
    (OUT / 'REPORT.md').write_text('\n'.join(lines) + '\n')


if __name__ == '__main__':
    main()
