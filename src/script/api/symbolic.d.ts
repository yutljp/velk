/** Symbolic execution needs z3 -in or bitwuzla on PATH, or VELK_SOLVER (a command line).
 * Bounds count IR statements and states; they do not use elapsed time.
 * Initial physical registers are zero except the stack pointer, as in emulation.
 * Only little-endian x86-64 and AArch64 are supported.
 */
interface SymbolicOptions {
  find?: (number | string)[];
  avoid?: (number | string)[];
  stdin?: number;
  /** Symbolic scalar argument indices, starting at zero. Register arguments only. */
  arguments?: number[];
  argumentValues?: (number | string)[];
  /** Length of each symbolic argv string, including argv[0]. Bytes cannot be zero. */
  argv?: number[];
  registers?: number[];
  registerValues?: Record<number, number | string>;
  memory?: {address: number | string; size: number}[];
  stepLimit?: number; // default 100000 per path
  pathLimit?: number; // default 256 total states
  addressLimit?: number; // default 8; 1..256
}
interface SymbolicInputs {
  stdin: number[];
  argv: number[][];
  arguments: Record<number, string>;
  memory: Record<string, number>;
  registers: Record<number, string>;
}
interface SymbolicReport {
  found: boolean;
  reason: string;
  inputs: SymbolicInputs | null;
  path: string[];
  paths: number;
  diagnostics: string[];
}
/** Opaque terms belong to one solver session; forks share that session. */
interface SymbolicTerm { readonly id: number; }
interface Symbolic {
  step(until?: (number | string)[]): {reason: string; address?: string; states?: Symbolic[]};
  fork(): Symbolic;
  symbolic(): SymbolicTerm;
  constant(value: number | string): SymbolicTerm;
  readRegister(index: number): SymbolicTerm;
  writeRegister(index: number, term: SymbolicTerm): void;
  readMemory(address: number | string, size: number): SymbolicTerm[];
  writeMemory(address: number | string, terms: SymbolicTerm[]): void;
  constrain(lhs: SymbolicTerm, condition: "eq" | "ne" | "ult" | "ule" | "ugt" | "uge" | "slt" | "sle" | "sgt" | "sge", rhs: SymbolicTerm, bits?: number): void;
  satisfiable(): boolean;
  /** Values in increasing unsigned order, as hex strings. Count is at most 256. */
  evaluate(term: SymbolicTerm, count?: number): string[];
  bounds(term: SymbolicTerm): [string, string] | null;
  address(): string;
  dispose(): void;
}
interface Binary {
  explore(start: string | number, options: SymbolicOptions): SymbolicReport;
  symbolic(start: string | number, options?: SymbolicOptions): Symbolic;
}
// Example (replace the addresses with addresses from b.getFunction or b.disasm):
// const b = velk.open("app.elf");
// b.explore("check", {find: ["0x401100"], stdin: 8});
// const s = b.symbolic("check", {arguments: [0]});
// const x = s.readRegister(7); // x86-64 System V first argument (rdi)
// s.constrain(x, "eq", s.constant(42));
// s.evaluate(x); // ["0x2a"]
// Limits: scalar IR expressions, branches, concrete-address memory and internal calls.
// getchar and read(fd=0) accept symbolic stdin. Other imports, flag-only branches,
// machine operations, switch statements and Apply operations with symbolic operands stop with diagnostics.
// Symbolic addresses fork up to addressLimit; hitting the bound is reported.
// A failed bounded search does not prove that a target is unreachable.

// Stops at imported addresses are rejected; use the call-site instruction address.
