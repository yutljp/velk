/** Hex string such as "0x1e0". */
type Addr = string;

interface Section {
  name: string;
  addr: Addr;
  size: number;
  executable: boolean;
}

interface Simplification {
  simplified: boolean;
  predicatesRemoved: number;
  dispatcherStatesRemoved: number;
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
  /** Recovered structure declarations shared across direct pointer flows. */
  structures?: string[];
  /** Proven predicate and constant dispatcher removals. */
  simplification: Simplification;
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
  entries: { name: string; isa: string; size: number; hash: string; tokens: string[]; bytes: number[]; calls: string[] }[];
  sources: string[];
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

interface Xref {
  function: Addr;
  block: Addr;
  statement: number;
  target: Addr;
  kind: "call" | "tailCall" | "resolvedCall" | "candidateCall" | "jumpTable" | "read" | "write" | "address";
  name: string | null;
}

interface NavigationFailure {
  function: Addr;
  error: string;
}

interface XrefResult {
  xrefs: Xref[];
  failures: NavigationFailure[];
}

interface GraphResult {
  functions: { addr: Addr; name: string | null }[];
  failures: NavigationFailure[];
}

interface PathResult {
  path: Addr[];
  failures: NavigationFailure[];
}

interface StringLiteral {
  addr: Addr;
  section: string;
  encoding: "ascii" | "utf8" | "utf16le";
  text: string;
  bytes: number;
  xrefs: Xref[];
}

interface StringsResult {
  strings: StringLiteral[];
  failures: NavigationFailure[];
}

interface ConstantMatch {
  instruction: Addr;
  value: Addr;
  operand: number;
  function: Addr | null;
}

interface ConstantsResult {
  matches: ConstantMatch[];
}

interface FunctionSummary {
  simplification: Simplification;
  addr: Addr;
  name: string | null;
  size: number | null;
  signature: Signature;
  callees: Addr[];
  imports: string[];
  strings: StringLiteral[];
  incomingXrefs: number;
  outgoingXrefs: number;
  failures: NavigationFailure[];
}

/** Names from runtime descriptors, without inferred data member sizes. */
interface CppClass {
  name: string;
  typeInfo: Addr;
  bases: CppBase[];
  vtables: CppVtable[];
}

interface CppBase {
  name: string;
  offset: number | null;
  isVirtual: boolean;
  isPublic: boolean;
  vtableOffset: number | null;
  vbtable: CppVirtualBase | null;
}

interface CppVirtualBase {
  pointerOffset: number;
  entryOffset: number;
  memberOffset: number;
}

interface CppVtable {
  address: Addr;
  offset: number;
  constructionDisplacement: number | null;
  methods: CppMethod[];
}

interface CppMethod {
  slot: number;
  address: Addr;
  name: string | null;
}

/** One complete pattern match within a loaded section. */
interface ByteSearchMatch {
  addr: Addr;
  section: string;
  function: Addr | null;
}
interface ByteSearchResult {
  matches: ByteSearchMatch[];
}
/** Complete values decoded within one loaded section. */
interface MemoryReadResult {
  addr: Addr;
  type: string;
  values: unknown[];
  bytes: number;
}
/** An exact data signature or a complete group of decoded immediates. */
interface DetectedConstant {
  name: string;
  addr: Addr;
  size: number;
  section: string | null;
  byteOrder: "bytes" | "little" | "big" | null;
  kind: "data" | "immediates";
  functions: Addr[];
}
interface DetectedConstantsResult {
  matches: DetectedConstant[];
  failures: Failure[];
}
