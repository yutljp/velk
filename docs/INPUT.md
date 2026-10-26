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

Opening a recognized UPX ELF or PE invokes `upx -d` from PATH. The
[UPX documentation](https://github.com/upx/upx/blob/devel/doc/upx.pod) describes
this direct decompression interface. The input executable is never run.
The IR emulator currently lifts immutable image bytes and does not implement
loader system calls, so it cannot execute UPX's remapping and code rewriting.
There is no general emulation-based unpacker.

The decoder runs with a five-second CPU limit, a ten-second elapsed limit,
a 128 MiB input/output limit, and core dumps disabled. Linux also sets a hard
512 MiB address-space limit. macOS cannot set that limit in the tested environment;
resident memory is sampled every millisecond and the child is killed above
512 MiB. This sampled check can overshoot and is not a hard allocation limit.
Decoding is supported on Linux and macOS; the tests here run on macOS.

Decoder failure, missing UPX, a timeout, an invalid output header, or output that
still looks packed returns an error. No partial image is returned. Successful
output goes through the normal loader. The CLI reports the packer, the release
version when present in the file's identification, and the direct decoding method on
standard error. Scripts expose the same information in `b.packing`; it is null
for ordinary inputs. Detection uses UPX header markers in sectionless ELF files and UPX PE section names or its short identification;
renamed or removed markers may prevent detection. Other packers are not decoded.

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
Tests build UPX fixtures for x86-64 and i386 ELF and PE, compare printed functions,
and exercise saving and damaged input. If UPX is absent, those fixture tests
print a skip message.
