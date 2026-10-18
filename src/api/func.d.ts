interface Func {
  addr: Addr;
  name: string | null;
  /** Bytes; null when the boundary is unknown. */
  size: number | null;
  /** Where the name or boundary came from: "symtab", "dyn", "entry", "go", "dwarf", "prologue". */
  nameSource: string[];

  /** Summary sized to roughly `budget` tokens (default 240); a larger budget adds disassembly lines. */
  card(opts?: { budget?: number }): Card;
  /** Pseudo-C. Throws when the function cannot be lifted. */
  decompile(): string;
  /** One line per instruction across the whole function, up to `limit` lines. */
  disasm(opts?: { limit?: number }): string[];
  /** The simplified intermediate representation, as text. */
  ir(): string;
  signature(): Signature;
  /** Constant addresses the function uses, with string literals resolved. */
  references(): Reference[];
  /** The string literals among `references()`. */
  strings(): string[];
  /** Stable hash of the function's normalized shape, to cite in claims. */
  evidence(): string;
}

// const f = velk.open("a.out").getFunction("0x1e0");
// f.signature();
// f.decompile();
