/** Symbolic execution needs z3 -in or bitwuzla on PATH, or VELK_SOLVER (a command line).
 * Bounds count IR statements and states; they do not use elapsed time.
 * Initial physical registers are zero except the stack pointer, as in emulation.
 * Only little-endian x86-64 and AArch64 are supported.
 */
interface SymbolicOptions {
  returns?: {eq: number | string} | {ne: number | string} | {lt: number | string} | {gt: number | string};
  stdinDescriptors?: number[];
  find?: (number | string)[];
  avoid?: (number | string)[];
  stdin?: number;
  /** Symbolic scalar argument indices, starting at zero. System V x86-64 and AAPCS64 also accept stack arguments. */
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
  /** Output bytes evaluated under the same assignment as the inputs. */
  stdout: number[];
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
interface BranchFeasibilityReport {
  branches: {address: string; taken: boolean; status: "unsat" | "unknown"; reason: string | null}[];
  complete: boolean;
  paths: number;
  diagnostics: string[];
}
interface Binary {
  /** Signed 64-bit lt/gt, bitwise eq/ne, on the outermost return. */
  solve(start: string | number, options: SymbolicOptions): SymbolicReport;
  branchFeasibility(start: string | number, options?: SymbolicOptions): BranchFeasibilityReport;
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
// Bounded libc models: scanf/fscanf/sscanf (%d/%u/%x/%s/%c, widths and suppression),
// fgets/gets/getline, getchar/read, strlen/strnlen, strcmp/strncmp/memcmp,
// memcpy/memmove/memset, strcpy/strncpy/strchr, atoi/strtol (base 10/16),
// ASCII toupper/tolower, puts/printf (%d/%u/%x/%s/%c/%%).
// Variadic AArch64 I/O requires ELF; strtol rejects the Windows data model.
// read uses descriptor zero or stdinDescriptors. Stream input requires stdin.
// Other imports, formats, flag-only branches, machine operations and symbolic Apply stop.
// Models charge stepLimit. Memory/string operations are bounded to 65536 bytes;
// unbounded string scans have a finite input-derived bound (at least 4096).
// Symbolic addresses fork up to addressLimit; hitting the bound is reported.
// A failed bounded search does not prove that a target is unreachable.

// Stops at imported addresses are rejected; use the call-site instruction address.
