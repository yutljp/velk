declare const velk: {
  /** Loads an ELF, PE or Mach-O file; reopening an unchanged file reuses the cached analysis. */
  open(path: string): Binary;
};

interface Binary {
  /** Absolute path of the file. */
  path: string;
  format: "elf" | "pe" | "coff" | "macho" | "other";
  arch: "x86_64" | "aarch64" | "unsupported";
  entry: Addr | null;

  sections(): Section[];

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

  /** A signature database built from this binary's named functions. */
  buildSignatures(): { database: SignatureDb; failures: Failure[] };

  /** Functions whose shape matches an entry of the database (or of the JSON file at that path). */
  identify(signatures: SignatureDb | string): { matches: Match[]; failures: Failure[] };
}

// const db = velk.open("libc.o").buildSignatures().database;
// velk.open("stripped.bin").identify(db).matches.map((m) => `${m.addr} ${m.matched}`);
