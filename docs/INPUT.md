# Raw bytes and packed executables

[日本語](INPUT.ja.md)

## Headerless code

Specify the instruction set and load address explicitly:

```sh
velk -D --raw-arch x86_64 --load-address 0x7000 code.bin 0x7000
```

`--raw-arch` accepts `x86_64`, `i386`, `aarch64`, `arm32` (A32), and `thumb`
(T32). The file must have no recognized object header. The bytes occupy one
readable, executable region named `raw`. The first byte is at
`--load-address`. Repeat `--entry ADDRESS` to supply function entries; without
entries, the load address is the entry. Existing prologue discovery also runs.
ARM entries with bit zero set select Thumb; physical addresses omit that bit.
ARM and AArch64 load addresses require instruction alignment. A 32-bit mapping
must fit the 32-bit address space. Invalid entries and address overflow fail.

The default byte order is little endian. `--raw-byte-order big` returns an error;
big-endian raw code is not supported. Calling conventions are System V on
x86-64, cdecl on i386, AAPCS64 on AArch64, and AAPCS32 on ARM32/Thumb.
The loader does not infer an operating system or import table from raw bytes.
Relocations and external code/data must already be resolved in the supplied image.

Scripts use the same options through `velk.open`:

```js
const b = velk.open("code.bin", {
  raw: {arch: "x86_64", base: "0x7000"}
});
b.getFunction("0x7000").decompile();
```

`raw.entries` is an optional array of addresses, and `raw.byteOrder` defaults to
`"little"`. Use strings for addresses beyond JavaScript's exact integer range.
Each mapping has a separate session cache. Strings are scanned in the raw region;
search, cross-references, memory reads, and emulation use its virtual addresses.
Emulation protects executable bytes: writes to the raw region stop with a memory
error. Use the emulated heap or stack for mutable input buffers.
Function annotations save the raw mapping in the project file, allowing reopening
with that project without repeating the options. An explicit mapping that differs
from the project's mapping fails; use a separate project for a different mapping.

MCP clients can run the JavaScript example with `velk_run_script`.
`velk_emulate` also accepts a `raw` object alongside `path`, `start`, and `options`.

## UPX recovery

Opening a recognized UPX ELF or PE first uses velk's built-in decoder. The input
executable is never run. Supported methods are NRV2B, NRV2D, NRV2E (32-bit and
byte-oriented bit streams), and LZMA with UPX properties `1a 03`, decoded by
`lzma-rs`. The decoder supports x86-64, i386, AArch64 and ARM32 little-endian ELF,
and x86-64 and i386 PE. Branch filters `0x26`, `0x46`, `0x49`, `0x50` (ARM), and
`0x52` (AArch64), and unfiltered blocks are supported. x86 branch-filter ranges
are limited to 16 MiB. Other header parameter values use the external fallback.

ELF recovery reads the stored program headers, load segments, gaps and remaining
file bytes. It requires the standard program-header layout and ordered,
non-overlapping load segments, with the headers in the first segment. PE recovery
reads the stored original headers and sections, restores the original entry point,
rebuilds named and ordinal imports, and restores HIGHLOW or DIR64 base relocations.
Like the reference decoder on these fixtures, PE recovery clears the debug and
IAT directory entries and rebuilds import names with zero hints and no separate
lookup table. Those original details are not restored.

Other UPX header layouts, methods, filters or LZMA properties use `upx -d` from
PATH as a fallback. PE resources, TLS, load configuration, bound or delayed imports,
CLR metadata, file overlays and other relocation encodings also require that
fallback. Malformed sizes, truncated blocks and checksum mismatches return errors.
No partial recovered file is returned. Successful output must parse as the same
executable format and have an entry point before normal loading begins.

Input and recovered files are limited to 128 MiB. Block output and LZMA dictionary
sizes are bounded; several buffers can coexist. The external fallback is available
on Linux and macOS, with a five-second CPU limit, a ten-second elapsed limit, and
core dumps disabled. Linux sets a hard 512 MiB address-space limit for that child.
On macOS, resident memory is sampled every millisecond and the child is killed
above 512 MiB; this sampled check can overshoot.

Detection uses identification markers and known ELF/PE header structures. Tests
also replace `UPX!` markers and rename PE sections. Removing or changing the format
fields themselves can prevent structural recognition. Other packers are not decoded.
The CLI reports the packer, the release version when present, and the decoder on
standard error. Scripts expose the same information in `b.packing`; it is null
for ordinary inputs.

Save the recovered executable while analyzing it:

```sh
velk -D --save-unpacked recovered.exe packed.exe add3
```

```js
const b = velk.open("packed.exe");
b.saveUnpacked("recovered.exe");
b.getFunction("add3").decompile();
```

Saving requires a successful recovery and a destination that does not exist.
The saved bytes are the complete decoder output before analysis relocations.
Self-built fixtures in `tests/data/upx` cover all four methods on every listed
format and architecture, PE imports and relocations, and branch filters. Their
recovered bytes are compared with `upx -d` output; ELF references also match the
original files. Rebuild them with `bash tests/scripts/make_upx_fixtures.sh OUTPUT_DIRECTORY`.
The additional packing tests require UPX on PATH and exercise CLI, JavaScript,
MCP, saved files and compiled printed C. The stored-fixture and decoder property
tests run without UPX. These checks were run on Linux; macOS was not checked here.
