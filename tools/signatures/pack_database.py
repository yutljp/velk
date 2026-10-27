"""Encode the same signatures as public JSON and compact embedded byte arrays."""

import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys
from collections import defaultdict, deque

import gzip_output

ROOT = Path(__file__).resolve().parents[2]
GENERATED = ROOT / 'target/library-signatures'
OUT = GENERATED / 'libraries'


def blob(value):
    data = value.encode() if isinstance(value, str) else bytes(value)
    return struct.pack('<I', len(data)) + data


def compact(entries):
    entries = sorted(entries, key=lambda e: (e['name'], e['bytes'], e['set']))
    sources = sorted({e['set'] for e in entries})
    binary = bytearray(b'VELKSIG1')
    binary += struct.pack('<I', len(sources))
    for source in sources:
        binary += blob(source)
    binary += struct.pack('<I', len(entries))
    for entry in entries:
        binary += blob(entry['name']) + blob(entry['set']) + blob(entry['bytes'])
        binary += struct.pack('<I', len(entry['calls']))
        for call in entry['calls']:
            binary += blob(call)
        binary += struct.pack('<I', len(entry.get('constants', [])))
        for constant in entry.get('constants', []):
            binary += blob(constant)
    return bytes(binary)


def body_key(entry):
    return entry['isa'], bytes(entry['bytes']), tuple(map(bytes, entry.get('constants', [])))


def select(database):
    entries = database['entries']
    by_set, by_name, by_body = defaultdict(set), defaultdict(set), defaultdict(set)
    for index, entry in enumerate(entries):
        by_set[entry['set']].add(index)
        by_name[entry['isa'], entry['name']].add(index)
        key = body_key(entry)
        by_body[key].add(index)
    counts = {key: len(indices) for key, indices in by_name.items()}
    callers = defaultdict(set)
    pending = deque()
    for index, entry in enumerate(entries):
        for call in entry['calls']:
            callers[entry['isa'], call].add(index)
            if not counts.get((entry['isa'], call), 0):
                pending.append(index)
    eligible = set(range(len(entries)))
    while pending:
        index = pending.popleft()
        if index not in eligible:
            continue
        eligible.remove(index)
        entry = entries[index]
        key = entry['isa'], entry['name']
        counts[key] -= 1
        if counts[key] == 0:
            pending.extend(callers[key])
    print(f'{len(eligible)} entries have every callee available', flush=True)

    def closure(indices):
        result, pending = set(indices), list(indices)
        while pending:
            index = pending.pop()
            entry = entries[index]
            key = body_key(entry)
            required = set(by_body[key])
            if index in eligible:
                for call in entry['calls']:
                    required.update(by_name[entry['isa'], call] & eligible)
            for index in required - result:
                result.add(index)
                pending.append(index)
        return result

    def size(indices, level=9):
        parts = defaultdict(list)
        for index in indices:
            parts[entries[index]['isa']].append(entries[index])
        return sum(len(gzip_output.compress(compact(part), compresslevel=level)) for part in parts.values())

    path = ROOT / 'tools/signatures/selection.json'
    if '--select' in sys.argv:
        path = GENERATED / 'selection.json'
    if '--select' not in sys.argv:
        selection = json.loads(path.read_text())
        return closure(set().union(*(by_set[name] & eligible for name in selection['sets'])))
    coverage = {name: set(matches) for name, matches in
                json.loads((ROOT / 'target/library-signatures/set-coverage.json').read_text()).items()}
    mandatory = {name for name in by_set if name.startswith(('zlib-', 'xxhash-', 'rust.'))}
    chosen = set(mandatory)
    selected = closure(set().union(*(by_set[name] & eligible for name in chosen)))
    covered = set().union(*(coverage.get(name, set()) for name in chosen))
    closures = {name: closure(indices & eligible) for name, indices in by_set.items() if name not in chosen}
    remaining = set(closures)
    budget = 2 * 1024 * 1024
    decisions = []
    costs = None
    while remaining:
        if costs is None:
            costs = {name: max(1, size(closures[name] - selected, level=1))
                     for name in remaining if coverage.get(name, set()) - covered}
        if not costs:
            break
        priority = min(0 if '.x86_64.' in name or '.aarch64.' in name else 1
                       for name in costs)
        candidates = [name for name in sorted(costs)
                      if (0 if '.x86_64.' in name or '.aarch64.' in name else 1) == priority]
        name = max(candidates, key=lambda name: len(coverage.get(name, set()) - covered) / costs[name])
        remaining.remove(name)
        costs.pop(name)
        benefit = len(coverage.get(name, set()) - covered)
        if not benefit:
            continue
        proposed = selected | closures[name]
        compressed = size(proposed)
        if compressed > budget:
            continue
        selected = proposed
        chosen.add(name)
        covered.update(coverage.get(name, set()))
        costs = None
        decisions.append({'set': name, 'additional_full_database_matches': benefit,
                          'embedded_bytes': compressed})
        print(f'{name}: {benefit} additional names; {compressed} bytes', flush=True)
    path.write_text(json.dumps({'budget_bytes': budget,
        'method': 'Remove entries with unavailable callees recursively. Choose x86-64 and AArch64 sets before i386 and ARM32 sets, then by additional full-database fixture matches per gzip-1 bytes of entries not yet selected, enforcing the budget with gzip-9. Retain body aliases and every eligible callee variant.',
        'sets': sorted(chosen), 'decisions': decisions}, indent=2) + '\n')
    return selected


def main():
    database = json.loads(gzip.decompress((GENERATED / 'base.json.gz').read_bytes()))
    expected = {f'{library}.{arch}.{level}'
                for library in ('musl', 'mbedtls', 'libsodium', 'openssl', 'rust')
                for arch in ('x86_64', 'aarch64', 'i386', 'arm32')
                for level in ('O0', 'O1', 'O2', 'O3', 'Os')}
    available = {path.name.removesuffix('.entries.json') for path in OUT.glob('*.entries.json')}
    if expected != available:
        raise SystemExit(f'incomplete library builds: missing {sorted(expected - available)}; unexpected {sorted(available - expected)}')
    manifest = json.loads((ROOT / 'tools/signatures/library_sources.json').read_text())
    sets = {}
    for path in sorted(OUT.glob('*.entries.json')):
        stem = path.name.removesuffix('.entries.json')
        library, arch, level = stem.split('.')
        entries = json.loads(path.read_text())
        database['entries'].extend(entries)
        database['sources'].append(stem)
        sets[stem] = {'library': library, 'arch': arch, 'optimization': level,
                      'provenance': 'library_sources.json',
                      'source_commit': manifest['rust'].split('commit-hash: ')[1].splitlines()[0]
                          if library == 'rust' else manifest['libraries'][library]['commit'],
                      'license': 'MIT OR Apache-2.0' if library == 'rust' else manifest['libraries'][library]['license'],
                      'entries': len(entries), 'set_ids': sorted({entry['set'] for entry in entries})}
    database['entries'].sort(key=lambda e: (e['set'], e['name'], e['bytes']))
    data = json.dumps(database, sort_keys=True, separators=(',', ':')).encode()
    (GENERATED / 'libraries.json.gz').write_bytes(gzip_output.compress(data))
    selected = select(database)
    defaults = dict(database, entries=[entry for index, entry in enumerate(database['entries']) if index in selected])
    (GENERATED / 'defaults.json.gz').write_bytes(gzip_output.compress(
        json.dumps(defaults, sort_keys=True, separators=(',', ':')).encode()))
    sizes = {}
    for arch in ['x86_64', 'aarch64', 'i386', 'arm32']:
        entries = [e for e in defaults['entries'] if e['isa'] == arch]
        binary = compact(entries)
        compressed = gzip_output.compress(binary)
        (GENERATED / f'{arch}.bin.gz').write_bytes(compressed)
        sizes[arch] = {'entries': len(entries), 'compressed_bytes': len(compressed), 'uncompressed_bytes': len(binary)}
    if sum(part['compressed_bytes'] for part in sizes.values()) > 2 * 1024 * 1024:
        raise SystemExit('embedded signatures exceed 2 MiB; rerun pack_database.py --select after measuring')
    (GENERATED / 'sets.json').write_text(json.dumps({'sets':sets,'embedded':sizes,'sha256':{str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted((ROOT / 'tools/signatures').glob('*.py')) + sorted((ROOT / 'tools/signatures/programs').glob('*'))}}, indent=2)+'\n')
    print(json.dumps(sizes, indent=2))


if __name__ == '__main__':
    main()
