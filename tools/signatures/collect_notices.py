"""Retain upstream copyright and license comments beside the generated sets."""

from pathlib import Path
import re
import subprocess

import gzip_output

ROOT = Path(__file__).resolve().parents[2]


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
        (ROOT / f'target/library-signatures/{library}.NOTICE.gz').write_bytes(gzip_output.compress(encoded))
    sysroot = Path(subprocess.check_output(['rustc', '--print', 'sysroot'], text=True).strip())
    data = (sysroot / 'share/doc/rust/COPYRIGHT-library.html').read_bytes()
    (ROOT / 'target/library-signatures/rust.NOTICE.html.gz').write_bytes(gzip_output.compress(data))
