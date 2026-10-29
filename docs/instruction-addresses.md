# Instruction addresses in pseudo-C

Add `--addresses` to append `/* 0x... */` to statement lines with a known
instruction origin:

```sh
velk -D --addresses tests/fixtures/l2_loop_x64.o sum_while
velk -D --json tests/fixtures/l2_loop_x64.o sum_while
```

Comments align within each function when they fit in 100 columns; longer lines
use one separating space. Without the option, pseudo-C is unchanged.

A replacement inherits the instruction that performs its printed effect: the
store, call, branch or return. Shared effects retain an address only when their
origins agree. Combined conditions, synthesized control flow and other effects
without a certain single origin have no address comment. Braces, declarations
and standalone `else` lines have none. A counted-loop header combining different
instructions also has none.

`-D --json` returns an object with `code` and `addresses`. Address comments are
enabled automatically. `addresses` maps one-based line numbers in `code` to lists
of hexadecimal address strings; lines without a known origin are absent. Line
numbers refer to the complete combined output, including its prelude.

The JavaScript option also works through MCP and `--serve`:

```js
const b = velk.open("tests/fixtures/l2_loop_x64.o");
b.getFunction("sum_while").decompile({addresses: true});
```

The option defaults to false on each call. Rust callers can use
`Binary::set_instruction_addresses(true)` before decompilation.
