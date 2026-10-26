# Byte search, memory values and standard constants

All three operations return JSON in the CLI. The JavaScript methods also work
through MCP's `velk_run_script` tool.

## Search

```sh
velk --search app '48 8b ?? 24' --section .text
velk --search app 'hello' --encoding ascii
velk --search app 'hello' --encoding utf16 --byte-order big
velk --search app 0x12345678 --encoding integer --width 4 --byte-order little
```

```js
const b = velk.open("app");
b.search("48 8b ?? 24", {section: ".text", start: "0x1000", end: "0x2000"});
```

Hex patterns use space-separated pairs of digits and `??` for one unknown byte.
ASCII rejects non-ASCII text. UTF-16 encodes surrogate pairs when needed. Integer
search accepts decimal or hexadecimal strings (negative values use two's
complement), with width 1, 2, 4 or 8 bytes, and rejects overflow. Results are
limited to 65536 matches; narrow the range or pattern if this limit is exceeded.
The default encoding is hex; byte order defaults to the image's order. Text searches do not include a terminating zero.

Loaded sections are searched, including zero-initialized sections without file
bytes. `--start` is inclusive,
`--end` exclusive, and `--section` selects an exact section name. Every byte of a
match must fit within both the range and one section. Results may overlap.
Each entry in `matches` contains `addr`, `section`, and the containing `function`
address (null outside discovered function ranges).

## Read values

```sh
velk --read-memory app 0x1000 --type u32 --count 4
velk --read-memory app record --type 'struct sample'
velk --read-memory app 0x2000 --type 'u16[3]'
```

```js
b.readMemory("record", "struct sample");
b.readMemory("0x1000", "u64", {count: 2});
```

Types are `u8/u16/u32/u64`, `i8/i16/i32/i64`, `f32/f64`, `pointer`, `cstring`,
`utf16`, fixed arrays `TYPE[N]`, and named structures from debug type information.
Count defaults to one. Structures return objects with named fields, arrays
return nested arrays, and strings advance through their terminating zero.
Unmapped addresses and reads crossing section boundaries fail with the address
and requested size. Zero-initialized sections read as zero. Strings must terminate within the same
section. C strings require valid UTF-8; UTF-16 rejects malformed surrogate pairs.

Reads use image byte order and pointer width. Unsigned 64-bit integers and pointers
are hex strings, signed 64-bit integers decimal strings, and smaller integers and
finite floats JSON numbers. Nonfinite floats are strings. The result contains
`addr`, `type`, `values`, and total `bytes` consumed. Limits are 65536 values
including nested fields/elements, 16 nesting levels and 16 MiB. Unsupported or
ambiguous debug layouts fail; bit-fields are omitted and unions are not supported.
Plain char fields with unknown signedness are rejected. Debug type loading
currently supports little-endian images. Annotations do not supply
memory layouts.

## Detect constants

```sh
velk --detect-constants app
```

```js
b.detectConstants().matches.slice(0, 10);
```

The signature list is in `src/tables/signatures.json`. It includes complete AES
forward/inverse S-boxes and round constants; MD5 and SHA-1/SHA-224/SHA-256/SHA-384/
SHA-512 initial values and round constants; CRC32, CRC32C, reflected CRC64-ECMA,
CRC64-ISO and forward CRC64-ECMA tables; base64/base64url alphabets; ChaCha/Salsa
key constants; TEA delta; and deflate length/distance bases stored as 16-bit values.
Numeric tables are checked in both byte orders. Partial or altered tables do not
match. The same data list controls all checks.

Non-executable loaded sections are searched for complete data signatures. Code is
searched through decoded instruction immediates: all words of an enabled
signature must occur within one discovered function. Big-endian instruction
immediates are not decoded. Values assembled from several instructions are not
combined. A single magic value, such as TEA delta,
is an exact value match; it does not establish the function's algorithm.

Matches give `name`, `addr`, `size`, `kind` (`data` or `immediates`), `section`,
`byteOrder`, and `functions`. Data functions come from xrefs into any byte of the
matched range. Immediate matches report their containing function and the first
matched instruction; section and byte order are null. Navigation failures are
returned separately as `failures`. Missing xrefs are possible when analysis fails.

Exact data matches give referenced globals names such as `aes_sbox` in printed C.
A longer match wins for signatures sharing an address. Only names change; values,
access widths and expressions retain their existing representation.

The constants follow [AES](https://doi.org/10.6028/NIST.FIPS.197-upd1),
[SHA](https://www.rfc-editor.org/rfc/rfc6234.html),
[MD5](https://www.rfc-editor.org/rfc/rfc1321.html),
[ChaCha](https://www.rfc-editor.org/rfc/rfc8439.html), and
[deflate](https://www.rfc-editor.org/rfc/rfc1951.html).
Fixture source is in `tests/cases/memory/`; `sh tests/make_memory_fixtures.sh`
builds x86-64, i386, AArch64, ARM, Thumb and big-endian AArch64 images in
`tests/data/byte_search/`. `cargo test --release --test memory -- --test-threads 3`
checks the CLI, JavaScript and MCP interfaces against those images.

The existing fixture corpus has ten matches recorded in
`tests/data/byte_search/corpus_matches.txt`: ChaCha constants in `go_probe`,
`go_stripped` and their ARM64 counterparts, and deflate distance/length bases in
`rust_demo`, `rust_probe` and `rust_probe_stripped`. The named Go reference is
`internal/chacha8rand.block`; the named Rust references are
`miniz_oxide::inflate::core::decompress` and `decompress_fast`. The stripped
variants contain the same bytes at the recorded locations. No other signatures
match this corpus.

PE file data lengths and mapped section lengths are kept distinct. Reads and
searches use zero-initialized tails without consuming the next file region.
`section_tail.dll` checks this boundary through all three interfaces, following
the [PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
