"""Retain upstream copyright and license comments beside the generated sets."""

import gzip
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def write(sources):
    for library in ('musl', 'mbedtls', 'libsodium', 'openssl'):
        source = sources / library
        notices = []
        for path in sorted(source.rglob('*')):
            if not path.is_file() or '.git' in path.parts:
                continue
            if any(path.match(pattern) for pattern in ('.env*', '*.pem', 'id_rsa', 'credentials.*', 'secrets.*', 'idapro.hexlic')):
                continue
            if path.suffix not in ('.c', '.h', '.S', '.s'):
                continue
            text = path.read_text(errors='replace')
            comments = []
            for comment in re.findall(r'/\*.*?\*/', text, flags=re.DOTALL):
                if re.search(r'copyright|license|permission|redistribution|public domain', comment, flags=re.IGNORECASE):
                    comments.append(comment)
            if comments:
                notices.append(str(path.relative_to(source)) + '\n' + '\n'.join(comments))
        encoded = '\n\n'.join(notices).encode()
        (ROOT / f'signatures/{library}.NOTICE.gz').write_bytes(gzip.compress(encoded, mtime=0))
    sysroot = Path(subprocess.check_output(['rustc', '--print', 'sysroot'], text=True).strip())
    data = (sysroot / 'share/doc/rust/COPYRIGHT-library.html').read_bytes()
    (ROOT / 'signatures/rust.NOTICE.html.gz').write_bytes(gzip.compress(data, mtime=0))
