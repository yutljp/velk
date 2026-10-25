declare const velk: {
  /** Loads an ELF, PE or Mach-O file; reopening an unchanged file reuses the cached analysis. */
  open(path: string): Binary;
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
