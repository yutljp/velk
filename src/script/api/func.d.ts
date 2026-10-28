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
  /** Exact library evidence or unresolved candidates. Only exact evidence supplies a name. */
  library?: LibraryEvidence;

  /** Execute this function with explicit state and limits. */
  emulate(options?: EmulationOptions): EmulationReport;
  /** Summary sized to roughly `budget` tokens (default 240); a larger budget adds disassembly lines. */
  card(opts?: { budget?: number }): Card;
  /** Standalone pseudo-C with support definitions. Throws when the function cannot be lifted.
   * For long MCP replies, page lines with .split("\n").slice(start, end).join("\n"). */
  decompile(opts?: { decodeStrings?: boolean }): string;
  origins(): { target: ProjectTarget; name?: string; c_type?: string }[];
  /** One line per instruction across the whole function, up to `limit` lines; unlimited if omitted. */
  disasm(opts?: { limit?: number }): string[];
  /** The optimized intermediate representation, as text. */
  ir(): string;
  signature(): Signature;
  /** Constant addresses the function uses, with string literals resolved. */
  references(): Reference[];
  /** The string literals among `references()`. */
  /** Referenced literals and recovered text; decode defaults to true. */
  strings(opts?: { decode?: boolean }): string[];
  /** Hash of the function's normalized shape; equal shapes give equal hashes. */
  shapeHash(): string;
  /** Ranked feature overlap; default limit is 10. First use indexes functions.
   * Omitting in searches this binary and excludes this function.
   * Scores are not probabilities or proof of equivalent behavior. */
  similar(opts?: { in?: Binary; limit?: number }): SimilarityReport;
  /** Inferred signature and navigation details; first use may build the whole-binary index. */
  summary(): FunctionSummary;
  xrefs(opts?: { from?: boolean }): XrefResult;
  callers(opts?: { depth?: number }): GraphResult;
  callees(opts?: { depth?: number }): GraphResult;
}

// const f = velk.open("a.out").getFunction("0x1e0");
// f.signature();
// f.decompile();

interface SimilarityReport {
  matches: SimilarityMatch[];
  failures: NavigationFailure[];
}

interface SimilarityMatch {
  function: Pick<Func, "addr" | "name" | "aliases" | "size" | "nameSources" | "library"> & { sizeEstimated?: true };
  score: number;
  evidence: SimilarityEvidence[];
}

interface SimilarityEvidence {
  feature: string;
  weight: number;
  similarity: number;
  shared: string[];
}
