"""Fetch the pinned inputs into target/ and verify their content hashes."""

import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ROOT / 'target/library-signatures/sources'
MANIFESTS = ROOT / 'tools/signatures'


def download(url, destination, expected):
    if destination.is_file():
        data = destination.read_bytes()
    else:
        with urllib.request.urlopen(url, timeout=120) as response:
            data = response.read()
    if hashlib.sha256(data).hexdigest() != expected:
        raise SystemExit(f'source checksum mismatch: {destination}')
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)


def checkout(destination, url, commit, expected):
    if not (destination / ".git").exists():
        subprocess.run(['git', 'init', str(destination)], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(['git', '-C', str(destination), 'fetch', '--depth=1', url, commit], check=True)
        subprocess.run(['git', '-C', str(destination), 'checkout', '--detach', 'FETCH_HEAD'], check=True)
    actual = subprocess.check_output(['git', '-C', str(destination), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != commit:
        raise SystemExit(f'wrong source commit: {destination}: {actual}')
    tree = subprocess.check_output(['git', '-C', str(destination), 'ls-tree', '-r', '-z', 'HEAD'])
    actual_hash = hashlib.sha256(tree).hexdigest()
    if actual_hash != expected:
        raise SystemExit(f'source tree checksum mismatch: {destination}')
    print(f'{destination.name}: {actual_hash}', flush=True)
    modified = subprocess.check_output(['git', '-C', str(destination), 'status', '--porcelain', '--untracked-files=all'])
    if modified:
        raise SystemExit(f'modified source files: {destination}')


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--all', action='store_true', help='also fetch the complete library checkouts')
    args = parser.parse_args()
    manifest = json.loads((MANIFESTS / 'sources.json').read_text())
    for relative, expected in manifest['sha256'].items():
        library, filename = relative.split('/', 1)
        record = manifest['repositories'][library]
        repository = record['url'].removeprefix('https://github.com/')
        url = f'https://raw.githubusercontent.com/{repository}/{record["commit"]}/{filename}'
        download(url, SOURCES / relative, expected)
    libraries = json.loads((MANIFESTS / 'library_sources.json').read_text())
    record = libraries['libraries']['musl']
    download(f'https://git.musl-libc.org/cgit/musl/plain/src/string/memcmp.c?id={record["commit"]}',
             SOURCES / 'references/memcmp.c', libraries['reference_sources']['musl/memcmp.c'])
    if not args.all:
        return
    for library, record in libraries['libraries'].items():
        destination = SOURCES / library
        checkout(destination, record['upstream'], record['commit'], record['tree_sha256'])
        for relative, commit in record.get('submodules', {}).items():
            url = subprocess.check_output(['git', '-C', str(destination), 'config', '-f', '.gitmodules',
                                          '--get', f'submodule.{relative}.url'], text=True).strip()
            if url.startswith('../'):
                from urllib.parse import urljoin
                url = urljoin(record['upstream'].rstrip('/') + '/', url)
            checkout(destination / relative, url, commit, record['submodule_tree_sha256'][relative])


if __name__ == '__main__':
    main()
