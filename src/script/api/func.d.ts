interface Func {
  addr: Addr;
  name: string | null;
  /** Other names that symbols give the same address. */
  aliases: string[];
  /** Bytes; null when the extent is unknown. */
  size: number | null;
  /** The size was guessed from the next function's start. */
  sizeEstimated?: true;
  /** Where the function was found: "symtab", "dynamic", "entry", "pclntab", "dwarf", "codeview", "unwind", "function-starts", "objc", "plt", "prologue", "signature". */
  nameSources: string[];

  /** Summary sized to roughly `budget` tokens (default 240); a larger budget adds disassembly lines. */
  card(opts?: { budget?: number }): Card;
  /** Standalone pseudo-C with support definitions. Throws when the function cannot be lifted.
   * For long MCP replies, page lines with .split("\n").slice(start, end).join("\n"). */
  decompile(): string;
  origins(): { target: ProjectTarget; name?: string; c_type?: string }[];
  /** One line per instruction across the whole function, up to `limit` lines; unlimited if omitted. */
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
  /** Inferred signature and navigation details; first use may build the whole-binary index. */
  summary(): FunctionSummary;
  xrefs(opts?: { from?: boolean }): XrefResult;
  callers(opts?: { depth?: number }): GraphResult;
  callees(opts?: { depth?: number }): GraphResult;
}

// const f = velk.open("a.out").getFunction("0x1e0");
// f.signature();
// f.decompile();
