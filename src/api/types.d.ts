/** Hex string such as "0x1e0". */
type Addr = string;

interface Section {
  name: string;
  addr: Addr;
  size: number;
  executable: boolean;
}

interface Card {
  fid: Addr;
  name: string | null;
  source: string[];
  size: number | null;
  size_estimated?: true;
  section: string | null;
  /** Why the function is hard to analyze, e.g. "boundary-unknown", "name-unknown". */
  hard_reasons: string[];
  blocks?: number;
  /** Instructions the lifter could not translate. */
  unsupported?: number;
  strings?: string[];
  name_hints?: string[];
  accesses?: string[];
  disasm_preview: string[];
  approx_tokens: number;
}

interface Reference {
  addr: Addr;
  section: string;
  text: string | null;
  /** Set when `addr` holds a pointer, to where it points. */
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
  size: number;
  /** The name the binary already gives the function, if any. */
  current: string | null;
  matched: string;
}
