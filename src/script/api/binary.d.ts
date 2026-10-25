declare const velk: {
  /** Loads an ELF, PE or Mach-O file; reopening an unchanged file reuses the cached analysis. */
  open(path: string, opts?: { project?: string }): Binary;
  /** Builds instruction signatures from a binary, static archive, or Rust rlib. */
  buildSignatures(path: string): { database: SignatureDb; failures: Failure[] };
};

interface Binary {
  /** Absolute path of the file. */
  path: string;
  format: "elf" | "pe" | "coff" | "macho" | "other";
  arch: "i386" | "x86_64" | "aarch64" | "arm32" | "unsupported";
  entry: Addr | null;

  sections(): Section[];
  /** Navigation is indexed once per unchanged binary. Depth defaults to one. */
  xrefs(target: string | number, opts?: { from?: boolean }): XrefResult;
  callers(target: string | number, opts?: { depth?: number }): GraphResult;
  callees(target: string | number, opts?: { depth?: number }): GraphResult;
  callPath(from: string | number, to: string | number, opts?: { depth?: number }): PathResult;
  strings(opts?: { contains?: string }): StringsResult;
  /** Pass a hex string for integers larger than JavaScript's safe integer range. */
  constants(value: string | number): ConstantsResult;
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
   * Throws when nothing matches or when several functions match.
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
