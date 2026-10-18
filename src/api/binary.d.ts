declare const velk: {
  /** Loads an ELF, PE or Mach-O file; reopening an unchanged file reuses the cached analysis. */
  open(path: string): Binary;
};

interface Binary {
  /** Canonical absolute path. */
  path: string;
  format: "elf" | "pe" | "coff" | "macho" | "other";
  arch: "x86_64" | "aarch64" | "unsupported";
  entry: Addr | null;

  sections(): Section[];

  /**
   * Every discovered function, in address order, filtered by all given fields.
   * `name` matches as a substring or a RegExp; `named: false` keeps unnamed functions only.
   */
  functions(filter?: { name?: string | RegExp; named?: boolean; minSize?: number }): Func[];

  /**
   * An address, an exact name, or a case-insensitive substring that matches exactly one name.
   * Throws when nothing matches, or lists the candidates when several do.
   */
  getFunction(nameOrAddr: string | number): Func;

  /** A signature database built from this binary's named functions. */
  buildSignatures(): SignatureDb;

  /** Functions whose shape matches an entry of `db` (a database or a path to its JSON file). */
  identify(db: SignatureDb | string): Match[];
}

// const b = velk.open("libfoo.so");
// const db = velk.open("libc.a.o").buildSignatures();
// b.identify(db).map((m) => `${m.addr} ${m.matched}`);
