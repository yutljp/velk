# Library function names

velk applies embedded instruction signatures when opening a binary with unnamed
functions. A unique, confirmed match supplies the function's name in the function
list and printed C. Existing symbol names remain in place. The `library` field
in function-list JSON, JavaScript `Func` objects and cards contains the candidate
names, source set identifiers and certainty. MCP exposes the same API.

```sh
velk -f app --json
velk --identify app
velk -D app XXH32
velk -f app --no-default-signatures
velk -f app --signatures first.json --signatures second.json
velk -f app --no-default-signatures --signatures target/library-signatures/libraries.json.gz
```

```js
const b = velk.open("app", {signatures: ["extra.json"]});
b.functions().filter(f => f.library).map(f => ({
  addr: f.addr, name: f.name, evidence: f.library
}));
const disabled = velk.open("app", {defaultSignatures: false});
```

`exact` means that the complete normalized instruction body, constants and
direct-call destinations agree, with one possible name in the enabled sets.
It is not a probability or a proof of source-code origin. Different source
functions can compile to identical code. `ambiguous` reports multiple remaining
names; `unconfirmed` reports bodies whose call destinations or uniqueness could
not be established. Neither supplies a name. Signature names are recomputed when
adding a database, so an added alias can withdraw a previously recovered name.

## Contents and limits

The full database contains builds of zlib 1.3.2's Adler-32 implementation and
xxHash 0.8.3's scalar XXH32/XXH64 implementation. They cover x86-64, AArch64,
x86-32 and little-endian A32 ARM with Clang 21 at O0, O1, O2, O3 and Os. xxHash is built with
`XXH_NO_STREAM` and `XXH_NO_XXH3`; zlib uses `Z_SOLO`, with `NO_DIVIDE` on the
32-bit targets. The script records the exact compiler package and input hashes
in [sources.json](../tools/signatures/sources.json). Additional sets contain musl, mbedTLS (including TF-PSA-Crypto), libsodium and
OpenSSL libcrypto at the exact source revisions in
[library_sources.json](../tools/signatures/library_sources.json). Their static archives
are built with GCC 15.2 for the same four architectures and five optimization
levels. OpenSSL uses `no-asm`, `no-shared`, `no-module`, `no-tests` and `no-apps`;
libsodium uses portable C implementations, with the configuration in
[build_libraries.py](../tools/signatures/build_libraries.py). mbedTLS uses its default configuration;
the unused ML-DSA submodule is absent.

Rust programs exercise strings, formatting, vectors, maps, sets, paths, I/O,
threads and mutexes at each target and optimization level. The installed Rust
standard library itself is precompiled; only the programs and generic code are
compiled at each level. Rust signatures contain only `std`, `core` and `alloc`
functions without generic arguments or closure-specific names, including concrete
trait implementations; other Rust
dependencies and the linked libc are excluded. Generic instantiations with
different type names can have identical bodies, so they are not shipped. Compiler
versions, target library hashes and source commits are recorded in the manifest.

These sets do not cover every build of those libraries. Different compilers, flags, vector implementations,
inlining and link-time optimization can prevent a match.

The matcher keeps non-address instruction bytes, including immediate
constants and internal branches. Direct calls and external branches have
their destination bytes masked; their destination names must agree through the
candidate call graph or an existing symbol. Graph checks also reject callers
of ambiguous destinations. Names duplicated at different addresses are not
assigned. Internal x86 branch targets must be instruction boundaries.

Fixed-width x86-64 PC-relative reads and AArch64 literal loads can be masked
only when the exact referenced bytes agree in loaded, read-only data. Writable
data, address construction and unsupported relocations are refused. Indirect
register operands remain in the signature. Thumb signatures and ARM PC-relative
data references are not supported. AArch64 and ARM matching requires little-endian data.

Bodies of at least four informative bytes can confirm callees. A function gets
a name only with at least 32 body bytes and 24 non-address instruction bytes.
Short bodies are used only for call confirmation and are not exposed as library candidates. On x86-64, leaf functions can also
match after swapping R10 and R11. Both registers must be fully defined before
branching or reading their initial values; arguments, return registers, stack
and preserved registers remain fixed. Calls and implicit scratch-register uses
refuse this alternative. An SMT test checks one straight-line return example;
it does not prove arbitrary control-flow graphs.

A32 follows reachable direct branches and calls from known starts and from A32
starts in the [ARM exception index](https://github.com/ARM-software/abi-aa/blob/main/ehabi32/ehabi32.rst).
This permits A32 library code after Thumb startup code. A new function start
requires a complete body match; its name still requires call confirmation.
Other architectures use the loader's existing function boundaries. Arbitrary
code bytes are not searched for names.

Go names come from its runtime function tables; no Go signature set is added.
Rust symbols and debug information are used when present. Stripped Rust can use
the instruction sets described above. The existing stripped Rust fixture is
measured separately; its counts are listed below.

## Sources, licenses and rebuilding

The executable embeds four compressed byte arrays, one per architecture. Only
the selected architecture is decoded, once per process. Opening a binary whose
functions are all named defers this load until explicit identification is
requested. There is no runtime download. [sets.json](../tools/signatures/sets.json)
records the compressed sizes, entry counts, source commits and licenses of every build.
The selected embedded subset is limited to 2 MiB by the packer and a unit test.
[selection.json](../tools/signatures/selection.json) records the selected sets and the
coverage estimates from the full-database measurements at each selection step.
The final embedded subset is measured separately. Entries with unavailable
callees are removed recursively before selection; body aliases and available
callee variants are retained. The selection considers x86-64 and AArch64 sets before i386 and ARM32,
then uses names per compressed byte within each group;
it is a greedy choice, not a proof of the best possible subset.

The full database is generated at `target/library-signatures/libraries.json.gz`;
it is not stored in the repository. `--signatures` and the JavaScript/MCP
`signatures` option accept both JSON and gzip-compressed JSON. The generated
`target/library-signatures/defaults.json.gz` contains the embedded entries;
a test compares every field with the compact data when that file is available.
The manifest counts and the 2 MiB limit are checked on every test run.
When the corpus tests are explicitly included, full-database measurements run when the generated full database is present;
otherwise they measure only the embedded sets.

License notices and upstream copyright comments accompany the data:
[zlib](../signatures/zlib.LICENSE), [xxHash](../signatures/xxhash.LICENSE),
[musl](../signatures/musl.LICENSE), [mbedTLS](../signatures/mbedtls.LICENSE),
[TF-PSA-Crypto](../signatures/tf-psa-crypto.LICENSE),
[libsodium](../signatures/libsodium.LICENSE), [OpenSSL](../signatures/openssl.LICENSE),
and Rust's [MIT](../signatures/rust.LICENSE-MIT) and
[Apache](../signatures/rust.LICENSE-APACHE) licenses. The selected terms are Zlib,
BSD-2-Clause, MIT (with the BSD notices listed by musl), Apache-2.0 for mbedTLS and
OpenSSL, ISC for libsodium, and MIT/Apache-2.0 for Rust. The compressed `*.NOTICE.gz`
files retain upstream copyright and permission comments; `rust.NOTICE.html.gz`
retains the installed standard library's notices. The data contains normalized
instruction bytes, so these notices are retained with it.

glibc is excluded. The [LGPL 2.1](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html)
addresses works based on the library; these sets contain normalized machine code.
No permission to redistribute such signatures independently of those obligations
was established.

The `signatures` Compose service uses the reference Dockerfile with the compiler
versions recorded in the manifests. The scripts reject different tool versions.
Sources are fetched at build time into `target/library-signatures/sources`.
The source manifest records URLs, commits and SHA-256 hashes: individual files for
zlib/xxHash and Git tree listings (including submodule entries) for the other
libraries. Existing checkouts must be clean. The local `include/string.h` supplies
only declarations for freestanding compilation.

```sh
docker compose run --rm signatures
cargo test --release --test library_signatures -- --include-ignored --test-threads 3
```

The first command builds the signature builder, fetches the sources, verifies
versions and hashes, and builds the archives, static programs and full database.
All generated files stay under `target/library-signatures/`, including compressed
reference, stripped and symbol-map files in `fixtures/`. The repository keeps the
40 zlib/xxHash variants (80 compressed files, 134,185 bytes) for default tests.
The native Adler-32 comparison links the system zlib development library.
The two tests that require the complete corpus are ignored by default; generate
it before running them with `--include-ignored`.

Reference files keep symbols but omit debug sections. Compilation remaps source
paths, including Rust sysroot paths. OpenSSL uses relative source names and
`SOURCE_DATE_EPOCH=0`. Completed library builds are cached in
`target/library-signatures/libraries`; remove that directory when changing build
flags or source revisions. `build_libraries.py --refresh-signatures` reuses cached
archives when only the signature builder changes. Tests write counts and set
coverage under `target/library-signatures/`, without blessing repository files.
`pack_database.py --select` writes a proposed selection there after full-database
measurement. The packer writes `*.bin.gz`, `sets.json` and databases there too.
To update embedded data, review and copy the generated byte arrays and notice files into
`signatures/` and the manifests into `tools/signatures/`, then rebuild and test.

To load the rebuilt full database:

```sh
velk -f app --no-default-signatures --signatures target/library-signatures/libraries.json.gz
```

## Measurements

The tests write zlib/xxHash, embedded and full-database counts under
`target/library-signatures/`. The additional libraries cover 100 combinations of
library, architecture and optimization level. Ground truth
is every library function symbol in the unstripped executable, including local
helpers and functions too short to match. Each recovered name is compared at its
address with the symbol table; wrapper functions are also checked for false names.
The measurement test rejects any wrong name. The tables below retain the recorded conclusions; generated counts are not repository snapshots.
It also checks CLI, JavaScript and MCP evidence, disabled defaults, ambiguity
after adding aliases, and generated C against zlib's result on native x86-64.

The C fixtures statically link programs using sorting, conversion and formatting
(musl); TLS/X.509 setup and SHA-256 (mbedTLS); hashing and secretbox (libsodium);
and SHA, AES and EVP digests (libcrypto). Archive entries cover more functions
than these programs exercise. The Rust ground truth includes every Rust function
symbol in the program, including dependencies and application functions that are
excluded from the standard library sets. The test also checks recovered names
outside each library against all reference symbols.

Native x86-64 fixtures run at all five levels. The generated C for musl `memcmp`
is compiled against its fetched source; zlib Adler-32 is compared with the system zlib on
10,000 inputs each. Cross-architecture measurements check names and addresses;
they do not execute the binaries. The cross-architecture tests do not require an emulator.

The 20 zlib variants have 26 correct names, 62 missed and no wrong names;
the 20 xxHash variants have 114 correct, 130 missed and no wrong names.

Across the 20 variants of each additional library, the recorded totals are:

| Library | Embedded correct | Full correct | Full missed | Wrong |
| --- | ---: | ---: | ---: | ---: |
| musl | 245 | 434 | 3,051 | 0 |
| mbedtls | 1,588 | 2,916 | 36,995 | 0 |
| libsodium | 352 | 664 | 13,064 | 0 |
| openssl | 5,428 | 10,061 | 261,682 | 0 |
| rust | 113 | 113 | 15,325 | 0 |

The existing stripped Rust fixture has 3 correct names, 0 wrong and 542 missed
out of 545 discovered functions. It was built with rustc 1.98.1; these sets use
rustc 1.99.1. Most functions remain unnamed under the conservative matching
rules above. Clean rebuilds of one variant of each new library produced identical
signature entries and compressed reference, stripped and symbol-map files;
the other variants were not rebuilt from scratch a second time.

The miss sample contains 100 misses per library, five evenly spaced addresses
in each architecture/optimization variant. It records the first failing check.
The samples distinguish missing starts, short bodies, unsupported PC-relative
operands, missing entries, excluded Rust names and call confirmation. Body
differences without a demonstrated cause remain unclassified; compiler flags,
register allocation and inlining are not inferred from a mismatch alone.

## Sampled causes

Each row contains 100 misses. PC/data groups unsupported PC-relative operands and unavailable constants. Other groups invalid boundaries and unexplained body differences. These are samples, not percentages of every missed function.

| Library | Missing start | Short | PC/data | Graph | Absent/excluded | Indirect | Other |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| musl | 28 | 19 | 17 | 7 | 10 | 16 | 3 |
| mbedtls | 27 | 20 | 8 | 24 | 6 | 1 | 14 |
| libsodium | 34 | 19 | 14 | 22 | 9 | 1 | 1 |
| openssl | 33 | 13 | 14 | 17 | 14 | 6 | 3 |
| rust | 25 | 5 | 25 | 0 | 45 | 0 | 0 |

The embedded arrays contain 61,915 entries in 2,093,031 bytes. The locally generated full JSON database is 13,066,235 compressed bytes.

## Results by architecture

Counts sum the five optimization levels. Every wrong count is zero.

| Library | Architecture | Embedded correct | Full correct | Full missed |
| --- | --- | ---: | ---: | ---: |
| musl | x86_64 | 110 | 112 | 542 |
| musl | aarch64 | 126 | 129 | 639 |
| musl | i386 | 4 | 130 | 544 |
| musl | arm32 | 5 | 63 | 1,326 |
| mbedtls | x86_64 | 807 | 807 | 6,906 |
| mbedtls | aarch64 | 781 | 781 | 9,043 |
| mbedtls | i386 | 0 | 773 | 6,966 |
| mbedtls | arm32 | 0 | 555 | 14,080 |
| libsodium | x86_64 | 174 | 177 | 1,759 |
| libsodium | aarch64 | 178 | 178 | 3,639 |
| libsodium | i386 | 0 | 180 | 1,754 |
| libsodium | arm32 | 0 | 129 | 5,912 |
| openssl | x86_64 | 2,725 | 2,725 | 57,863 |
| openssl | aarch64 | 2,703 | 2,703 | 61,020 |
| openssl | i386 | 0 | 2,624 | 57,947 |
| openssl | arm32 | 0 | 2,009 | 84,852 |
| rust | x86_64 | 34 | 34 | 3,846 |
| rust | aarch64 | 36 | 36 | 3,847 |
| rust | i386 | 19 | 19 | 3,818 |
| rust | arm32 | 24 | 24 | 3,814 |

The size budget prioritizes x86-64 and AArch64. The 32-bit targets retain the smaller mandatory sets; load the full database for broader coverage. The existing stripped Rust fixture has 3 correct names and 542 missed with either database.

A recorded latency run used one warm-up and 15 samples per executable. Median
single-function times with embedded signatures were 0.646 seconds for
`go_probe main.main` and 0.076 seconds for `rust_probe rust_probe::main`.
These timings describe that run, rather than a limit for other machines.
