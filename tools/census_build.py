"""Build freestanding ELF fixtures for the census on available Clang targets."""
import concurrent.futures
import itertools
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / 'target/census'
DATA = ROOT / 'tests/data'
CORPUS = OUT / 'cross'
TARGETS = {'x86_64': 'x86_64-unknown-linux-gnu', 'aarch64': 'aarch64-unknown-linux-gnu',
           'i386': 'i386-unknown-linux-gnu', 'arm32': 'armv7-unknown-linux-gnueabihf'}


def run(command):
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                errors='replace', timeout=60)
        return result.returncode, result.stderr
    except subprocess.TimeoutExpired:
        return None, 'timeout'


def main():
    CORPUS.mkdir(parents=True, exist_ok=True)
    builds = []
    paths = []
    sources = sorted((DATA / 'crackmes').glob('*.c'))
    wrappers = CORPUS / 'symbolic_main.c'
    wrappers.write_text('extern int getchar_password(void); int main(void) { return getchar_password(); }\n')
    for arch, target in TARGETS.items():
        flags = ['--target=' + target, '-ffreestanding', '-fno-builtin', '-fPIC']
        support = CORPUS / (arch + '-support.o')
        code, error = run(['clang', *flags, '-O2', '-c', str(DATA / 'symbolic_streams.c'), '-o', str(support)])
        if code != 0:
            builds.append({'name': arch + '-support', 'status': code, 'error': error})
            continue
        shared = CORPUS / ('lib' + arch + '-input.so')
        code, error = run(['ld.lld', '-shared', '-soname', shared.name, str(support), '-o', str(shared)])
        if code != 0:
            builds.append({'name': arch + '-shared', 'status': code, 'error': error})
            continue
        assembly = CORPUS / (arch + '-assembly.o')
        command = ['clang', '--target=' + target, '-c', str(DATA / 'census.S'), '-o', str(assembly)]
        code, error = run(command)
        commands = [{'command': command, 'status': code, 'error': error}]
        name = arch + '-assembly'
        if code == 0:
            path = CORPUS / name
            command = ['ld.lld', '-e', 'main', str(assembly), '-o', str(path)]
            code, error = run(command)
            commands.append({'command': command, 'status': code, 'error': error})
            if code == 0:
                paths.append({'name': name, 'path': str(path), 'kind': 'assembly'})
        builds.append({'name': name, 'commands': commands, 'status': code, 'error': error})

        def build(item):
            source, opt, protector, pie = item
            label = source.stem if source else 'symbolic'
            stem = f'{arch}-{label}-O{opt}-ssp-{protector}-pie-{pie}'
            output = CORPUS / (stem + '.o')
            selected = [source] if source else [DATA / 'symbolic.c', DATA / 'symbolic_io.c',
                                                DATA / 'symbolic_libc.c', wrappers]
            if source is None and arch in ('x86_64', 'aarch64'):
                selected.append(DATA / 'symbolic_calls.S')
            objects = []
            logs = []
            for index, input_file in enumerate(selected):
                obj = output if len(selected) == 1 else CORPUS / (stem + f'-{index}.o')
                command = ['clang', '--target=' + target, '-O' + opt, '-g', '-ffreestanding',
                           '-fno-builtin', '-fno-optimize-sibling-calls',
                           '-fstack-protector-all' if protector == 'on' else '-fno-stack-protector',
                           '-fPIE' if pie == 'on' else '-fno-pie', '-c', str(input_file), '-o', str(obj)]
                code, error = run(command)
                logs.append({'command': command, 'status': code, 'error': error})
                if code != 0:
                    return [], [{'name': stem, 'commands': logs, 'status': code}]
                objects.append(obj)
            made = []
            attempts = []
            for linkage in ('static', 'dynamic'):
                name = stem + '-' + linkage
                path = CORPUS / name
                command = ['ld.lld', '-e', 'main']
                if pie == 'on':
                    command.append('-pie')
                command.extend(map(str, objects))
                command.extend([str(support)] if linkage == 'static' else ['-L' + str(CORPUS), '-l' + arch + '-input'])
                command.extend(['-o', str(path)])
                code, error = run(command)
                attempts.append({'name': name, 'commands': logs + [{'command': command, 'status': code, 'error': error}], 'status': code})
                if code == 0:
                    made.append({'name': name, 'path': str(path), 'kind': 'symbolic' if source is None else 'crackme'})
            return made, attempts

        items = itertools.product([*sources, None], ['0', '2', 's'], ['on', 'off'], ['on', 'off'])
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            for made, attempts in pool.map(build, items):
                paths.extend(made)
                builds.extend(attempts)
                print(f'{arch}: {len(builds)} attempts, {len(paths)} binaries', flush=True)
        (OUT / 'cross-builds.json').write_text(json.dumps(builds, indent=2))
        (OUT / 'cross-manifest.json').write_text(json.dumps(paths, indent=2))
    (OUT / 'cross-builds.json').write_text(json.dumps(builds, indent=2))
    (OUT / 'cross-manifest.json').write_text(json.dumps(paths, indent=2))


if __name__ == '__main__':
    main()
