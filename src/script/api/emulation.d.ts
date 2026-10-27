/** Use strings for values above 2^53 - 1. Addresses are virtual addresses. */
type EmulationWord = number | string;
interface EmulationOptions {
  /** Stdin consumed in order; absent means EOF. At most 16 MiB. */
  stdin?: {text: string} | {hex: string} | {file: string};
  /** Main arguments including argv[0]; mutually exclusive with arguments. */
  argv?: string[];
  reads?: EmulationRead[];
  /** Stop before executing one of these instruction addresses. */
  end?: EmulationWord[];
  /** Full register names, for example rax, eax (i386), x0, sp, or r0. */
  registers?: Record<string, EmulationWord>;
  /** Scalar integer/pointer arguments, in the recovered convention's order. */
  arguments?: EmulationWord[];
  /** Writes must target writable mapped memory. Integers are little endian. */
  memory?: { address: EmulationWord; bytes?: number[]; value?: EmulationWord; width?: 1 | 2 | 4 | 8 }[];
  /** IR statements plus hook work units; default 100000. */
  stepLimit?: number;
  /** Elapsed milliseconds, checked during execution and after lifting; default 1000. */
  timeLimitMs?: number;
  trace?: boolean;
  /** Explicit integer results keyed by imported symbol name or hexadecimal address. */
  callReturns?: Record<string, EmulationWord>;
  /** Skip unhandled calls with a zero result; hooks still run. Default false. */
  skipCalls?: boolean;
}
interface EmulationReport {
  /** Captured bytes decoded as UTF-8 with replacement for invalid sequences. */
  stdout: string;
  stderr: string;
  reads: {address: string; bytes: number[]; value: string | number[] | string[]}[];
  /** Hexadecimal values, or "unknown" for unspecified call effects. */
  registers: Record<string, string>;
  /** Hexadecimal integer result, or "unknown" when no result is defined. */
  returnValue: string;
  memory: { address: string; bytes: number[]; hex: string }[];
  steps: number;
  reason: "return" | "end address" | "trap" | "step limit" | "time limit" | "error";
  address: string;
  error: string | null;
  trace: string[];
  heapBase: string;
  heapSize: number;
  stackPointer: string;
}

/** Read mapped memory after execution; omit length to stop before NUL. */
interface EmulationRead {
  /** Exactly one of address, symbol, register. */
  address?: EmulationWord;
  symbol?: string;
  register?: string;
  length?: number;
  format?: "string" | "bytes" | "hex" | "integers";
  /** Required for integers; unsigned little endian, returned as decimal strings. */
  width?: 1 | 2 | 4 | 8;
}
