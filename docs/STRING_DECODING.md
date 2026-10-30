# Automatic string recovery

English | [日本語](STRING_DECODING.ja.md)

String recovery runs loaded instructions through the IR interpreter. It observes
calls with buffer pointers and a known following integer byte length, and inline buffer
writes before a call that uses the buffer. Decoder names do not select candidates.
The result is a comment containing the text and the machine instruction address.
When several calls have the same target, a unique named buffer can identify the
call. Otherwise comments follow the function, because the rendered IR no longer
keeps the instruction address of each call.
Comments do not replace instructions, calls or data.

```sh
velk --strings app.elf --contains sample
velk -D app.elf case_xor
velk --strings app.elf --no-string-decoding
velk -D app.elf case_xor --no-string-decoding
```

The strings result keeps file-backed literals in `strings`. `decodedStrings`
contains recovered text, `addr` (output buffer), `function` (containing function),
`site` (decoder call or subsequent buffer use), `decoder`, `decoderName`, `stack`
`key` (the constant argument immediately after a known length, when present),
and `encoding`. `decodedConfigurations` contains decoded JSON or delimited
key/value buffers with at least two string or integer fields when a tokenize,
integer-conversion or formatted-scan function also receives a pointer into the buffer.
Each result lists the observed function name in `evidence`, along with the same decoder and call-site
provenance. JSON object paths are flattened with dots;
arrays use indexed paths. Stack and heap addresses refer to the emulator, not a
runtime process. `--contains` filters each result by its decoded text.
`decodedStrings` also lists parsing functions that received pointers into the
buffer in its `evidence` field.

The shared `velk::string_decoding::configurations` function extracts these fields
from recovered strings for other analyses, including indicator extraction.

```js
const b = velk.open("app.elf");
b.strings({contains: "sample"}).decodedStrings;
```

```js
const b = velk.open("app.elf");
b.strings({decode: false}).decodedStrings;
```

```js
const b = velk.open("app.elf");
b.getFunction("case_xor").decompile({decodeStrings: false});
```

MCP clients use these same JavaScript operations through `velk_run_script`.
`velk_read_api` describes their fields and options.

## Acceptance and bounds

Registers and uninitialized stack or heap bytes are unknown during recovery.
Loaded data starts from its file image, including zero-filled sections. Execution
before a function's entry, including writes by earlier invocations, is not
reconstructed. Unknown
control flow or input, unsupported instructions, traps, unhandled calls and limits
stop execution. A decoder result requires normal return and writes confined to its
argument buffers, local stack and by-value stack arguments. Return destinations
must be known and unchanged. A completed decoder call can be recorded even
if later instructions in its caller stop. Inline results are observed before the
buffer is passed to a subsequent call; that call is not skipped or guessed.

Text must have a known terminator, at least four characters and valid UTF-8 or
little-endian UTF-16, without control characters except tab and line breaks.
An unchanged known zero byte (or zero UTF-16 unit) immediately after the byte
count can terminate the result. Writes beyond the recovered terminator within
an output buffer cause that result to be rejected.
Recovery requires transformed bytes. Literal bytes individually assembled on the
stack additionally qualify at recognized C string uses (`puts`, `strlen`,
`strcmp`, `strncmp`, `strcpy`). Ordinary byte copies do not qualify.

Each function has a 200000-statement budget.
Recovery tracks at most 64 KiB of written bytes, 200000 byte-write events, 4096 bytes
per output buffer and 64 results per function. A whole-binary strings scan examines
every function. Interpreter code-size and call-depth
limits also apply. The caller's deadline is checked at execution and lifting
boundaries. Results are cached per function.
Budgets can cause misses. Go calling conventions, unknown lengths, unterminated
buffers and strings shorter than four characters are left unchanged.

## Reproducible examples

`sh tests/scripts/make_string_decoding_fixtures.sh` builds the example functions in
`target/string-decoding-fixtures/`. Substitute
`target/string-decoding-fixtures/x86_64.O0.elf` for `app.elf` above.
`cargo test --release --test string_decoding -- --test-threads 3 --nocapture`
compares recovered text with source and native execution, reports found/wrong/missed
counts per style and architecture, and runs the shell and JavaScript examples.
