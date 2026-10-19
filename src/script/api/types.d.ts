/** Hex string such as "0x1e0". */
type Addr = string;

interface Section {
  name: string;
  addr: Addr;
  size: number;
  executable: boolean;
}

interface Card {
  addr: Addr;
  name: string | null;
  aliases?: string[];
  nameSources: string[];
  size: number | null;
  sizeEstimated?: true;
  section: string | null;
  /** Why the function is hard to analyze: "boundary-unknown", "name-unknown". */
  hardReasons: string[];
  /** Why the function could not be lifted; the IR fields are then absent. */
  liftError?: string;
  blocks?: number;
  /** Instructions the lifter could not translate. */
  unsupported?: number;
  strings?: string[];
  /** Identifier-like words taken from the strings. */
  nameHints?: string[];
  /** Fields read through pointer parameters, as "param +offset:type". */
  accesses?: string[];
  disasmPreview: string[];
  approxTokens: number;
}

interface Reference {
  addr: Addr;
  section: string;
  text: string | null;
  /** Set when `addr` holds a pointer: where it points. */
  pointer: Addr | null;
}

interface Signature {
  return: string;
  params: { name: string; type: string }[];
}

interface SignatureDb {
  version: number;
  entries: { name: string; isa: string; size: number; hash: string; tokens: string[] }[];
}

interface Match {
  addr: Addr;
  size: number | null;
  /** The name the binary already gives the function, if any. */
  current: string | null;
  matched: string;
}

/** A function whose analysis failed, so it took no part in the result. */
interface Failure {
  addr: Addr;
  error: string;
}
