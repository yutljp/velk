/** Use strings for values above 2^53 - 1. Addresses are virtual addresses. */
type EmulationWord = number | string;
interface EmulationOptions {
  /** Thread-local mapping: 8 KiB for x86 Windows PE, otherwise 4 KiB. Chosen automatically. */
  tlsBase?: number | string;
  /** Stack guard, truncated to pointer width; default "0x6a09e667bb67ae00". */
  /** Fixed Unix time in seconds; default zero. */
  time?: number | string;
  canary?: number | string;
  /** Stdin consumed in order; absent means EOF. At most 16 MiB. */
  stdin?: {text: string} | {hex: string} | {file: string};
  /** Additional descriptors bound to the same stdin stream. */
  stdinDescriptors?: number[];
  /** Virtual path-to-byte map; every opened path needs an entry. No host file access.
   * Modes r/w/a/r+ and b variants preserve bytes without text translation. */
  files?: Record<string, number[]>;
  /** Process parameters for x86-64/i386 PE emulation; no host environment access. */
  windows?: {
    /** Full command line including the executable name; default "program.exe". */
    commandLine?: string;
    /** Default "C:\\program.exe". */
    imagePath?: string;
    /** Case-insensitive names; defaults to an empty environment. */
    environment?: Record<string, string>;
  };
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
  antiAnalysis?: {
    debuggerPresent?: boolean;
    ptraceTracemeSucceeds?: boolean;
    parentProcessId?: number;
    dumpable?: boolean;
    preload?: string | null;
    clockTicksPerInstruction?: number;
    tracerProcessId?: number;
  };
}
interface EmulationReport {
  /** File contents committed by fflush/fclose; no host writes. */
  files: Record<string, number[]>;
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
  reason: "return" | "exit" | "end address" | "trap" | "stack check failed" | "step limit" | "time limit" | "error";
  address: string;
  error: string | null;
  trace: string[];
  heapBase: string;
  heapSize: number;
  stackPointer: string;
  antiAnalysis: string[];
  /** DLL-qualified Windows calls in order, with hexadecimal scalar arguments.
   * Variadic CRT calls list their fixed arguments. Unknown signatures have no arguments. */
  apiCalls: {name: string; arguments: string[]}[];
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
