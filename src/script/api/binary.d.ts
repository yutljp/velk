declare const velk: {
  /** Loads an ELF, PE/COFF or Mach-O file without decompiling every function.
   * Reopening an unchanged file reuses cached analysis, even across scripts.
   * Universal Mach-O files open the slice for this machine unless opts.arch picks another. */
  open(path: string, opts?: { project?: string; arch?: "arm64" | "arm64e" | "x86_64" }): Binary;
  /** Builds instruction signatures from a binary, static archive, or Rust rlib. */
  buildSignatures(path: string): { database: SignatureDb; failures: Failure[] };
};

interface Binary {
  /** Absolute path of the file. */
  path: string;
  format: "elf" | "pe" | "coff" | "macho" | "other";
  arch: "i386" | "x86_64" | "aarch64" | "arm32" | "unsupported";
  entry: Addr | null;
  slices: { arch: string; cpuType: number; cpuSubtype: number; offset: number; size: number }[];
  sliceOffset: number;

  /** C++ classes described by RTTI; empty when unsupported or absent. */
  classes(): CppClass[];
  sections(): Section[];
  /** Compare two versions. Changed functions come first; ambiguous matches remain unmatched.
   * carryAnnotations writes only unannotated targets in the second binary's project. */
  compare(other: Binary, opts?: { carryAnnotations?: boolean }): ComparisonReport;
  /** Incoming references by default; from:true returns references made by the containing function.
   * The first navigation query builds a whole-binary index and can be slow.
   * Results carry failures; slice the xrefs array before returning it through MCP. */
  xrefs(target: string | number, opts?: { from?: boolean }): XrefResult;
  /** Call graph neighbors, excluding candidate indirect calls. Depth defaults to one. */
  callers(target: string | number, opts?: { depth?: number }): GraphResult;
  callees(target: string | number, opts?: { depth?: number }): GraphResult;
  /** Shortest call path including endpoints; empty if unreachable. Default depth: 32. */
  callPath(from: string | number, to: string | number, opts?: { depth?: number }): PathResult;
  /** Heuristic text candidates; contains is a case-sensitive substring. Slice result.strings. */
  strings(opts?: { contains?: string }): StringsResult;
  /** Decoded immediate matches, excluding branch displacements; slice result.matches.
   * Pass a hex string for integers larger than JavaScript's safe integer range. */
  constants(value: string | number): ConstantsResult;
  /** Writes immediately to the project file; pass open's project option for a writable location.
   * Name edits are reflected in subsequent lookups, summaries, navigation and C. */
  projectSet(annotation: ProjectAnnotation): { ok: boolean };
  projectGet(target: ProjectTarget): ProjectAnnotation | null;
  projectList(): ProjectAnnotation[];
  projectRemove(target: ProjectTarget): { removed: boolean };
  projectExport(): AnalysisProject;
  projectImport(project: AnalysisProject): { ok: boolean };

  /**
   * Every discovered function in address order, filtered by all given fields.
   * `name` matches a name or alias as a substring or a RegExp; `named: false` keeps unnamed functions only.
   */
  functions(filter?: { name?: string | RegExp; named?: boolean; minSize?: number }): Func[];

  /**
   * An address, an exact name, or a case-insensitive substring that matches exactly one name.
   * Addresses must be virtual function starts, not file offsets. No wildcard selector.
   * Throws with discovery guidance when nothing matches or when several functions match.
   */
  getFunction(nameOrAddr: string | number): Func;

  /** Instruction signatures from named functions at least 32 bytes long. */
  buildSignatures(): { database: SignatureDb; failures: Failure[] };

  /** Unique instruction matches with agreeing direct calls. Applies names to unnamed functions
   * and invalidates the function-list cache; subsequent decompilations use the names. */
  identify(signatures: SignatureDb | string): { matches: Match[]; failures: Failure[] };
}

// const db = velk.open("libc.o").buildSignatures().database;
// velk.open("stripped.bin").identify(db).matches.map((m) => `${m.addr} ${m.matched}`);

type ProjectStorage =
  | { kind: "register"; register: number }
  | { kind: "stack"; offset: number }
  | { kind: "definition"; register: number; block: Addr; statement: number };
type ProjectTarget =
  | { kind: "function" | "global" | "comment" | "classification"; address: Addr }
  | { kind: "parameter" | "local"; function: Addr; storage: ProjectStorage }
  | { kind: "signature"; function: Addr }
  | { kind: "declaration"; name: string };
type ProjectAnnotation = { target: ProjectTarget; name?: string; c_type?: string; text?: string };
type AnalysisProject = { version: 1; binary_sha256: string; annotations: ProjectAnnotation[] };

type FunctionComparison = {
  first: ComparedFunction; second: ComparedFunction;
  rule: "name" | "shape" | "references"; similarity: number;
  cDiff: string; blockDiff: string;
};
type AnnotationTransfer = { source: ProjectTarget; destination: ProjectTarget | null; reason: string };
type ComparisonReport = {
  changed: FunctionComparison[]; identical: FunctionComparison[];
  onlyFirst: ComparedFunction[]; onlySecond: ComparedFunction[]; failures: string[];
  transfer: { copied: AnnotationTransfer[]; skipped: AnnotationTransfer[] } | null;
};
type ComparedFunction = Pick<Func, "addr" | "name" | "aliases" | "size" | "sizeEstimated" | "nameSources">;
