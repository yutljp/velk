"""Encode deterministic gzip data using the distributed files' Unix header."""

import gzip


def compress(data, compresslevel=9):
    encoded = bytearray(gzip.compress(data, compresslevel=compresslevel, mtime=0))
    # Python versions differ in the operating-system byte of the gzip header.
    encoded[9] = 3
    return bytes(encoded)
