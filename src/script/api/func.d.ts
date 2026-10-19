interface Func {
  addr: Addr;
  name: string | null;
  /** Other names that symbols give the same address. */
  aliases: string[];
  /** Bytes; null when the extent is unknown. */
  size: number | null;
  /** The size was guessed from the next function's start. */
  sizeEstimated?: true;
  /** Where the function was found: "symtab", "dynamic", "entry", "pclntab", "dwarf", "prologue". */
  nameSources: string[];

  /** Summary sized to roughly `budget` tokens (default 240); a larger budget adds disassembly lines. */
  card(opts?: { budget?: number }): Card;
  /** Pseudo-C. Throws when the function cannot be lifted. */
  decompile(): string;
  /** One line per instruction across the whole function, up to `limit` lines. */
  disasm(opts?: { limit?: number }): string[];
  /** The optimized intermediate representation, as text. */
  ir(): string;
  signature(): Signature;
  /** Constant addresses the function uses, with string literals resolved. */
  references(): Reference[];
  /** The string literals among `references()`. */
  strings(): string[];
  /** Hash of the function's normalized shape; equal shapes give equal hashes. */
  shapeHash(): string;
}

// const f = velk.open("a.out").getFunction("0x1e0");
// f.signature();
// f.decompile();
