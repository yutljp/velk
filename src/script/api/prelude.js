"use strict";
(() => {
  const native = globalThis.__velk;
  delete globalThis.__velk;
  const call = (op, args) => {
    try { return JSON.parse(native(JSON.stringify({ op, ...args }))); }
    catch (error) {
      try { const detail = JSON.parse(error.message); if (detail.code) Object.assign(error, detail); } catch (_) {}
      throw error;
    }
  };
  const address = (value) => (typeof value === "number" ? "0x" + value.toString(16) : value);

  class Func {
    #bin;
    constructor(bin, row) {
      this.#bin = bin;
      Object.assign(this, row);
    }
    #call(op, extra = {}) {
      return call(op, { bin: this.#bin, addr: this.addr, ...extra });
    }
    emulate(options = {}) { return call("emulate", { bin: this.#bin, start: this.addr, options }); }
    card({ budget } = {}) { return this.#call("card", { budget }); }
    decompile({ decodeStrings = true } = {}) { return this.#call("decompile", { decodeStrings }); }
    disasm({ limit } = {}) { return this.#call("disasm", { limit }); }
    ir() { return this.#call("ir"); }
    origins() { return call("project", { bin: this.#bin, action: "origins", value: this.addr }); }
    signature() { return this.#call("signature"); }
    references() { return this.#call("references"); }
    strings({ decode = true } = {}) { return this.#call("strings", { decode }); }
    shapeHash() { return this.#call("shapeHash"); }
    summary() { return call("navigate", { bin: this.#bin, query: { kind: "summary", target: this.addr } }); }
    xrefs({ from = false } = {}) { return call("navigate", { bin: this.#bin, query: { kind: "xrefs", target: this.addr, from } }); }
    callers({ depth = 1 } = {}) { return call("navigate", { bin: this.#bin, query: { kind: "callers", target: this.addr, depth } }); }
    callees({ depth = 1 } = {}) { return call("navigate", { bin: this.#bin, query: { kind: "callees", target: this.addr, depth } }); }
  }

  class Symbolic {
    #bin;
    #id;
    constructor(bin, id) { this.#bin = bin; this.#id = id; }
    #call(action, extra = {}) { return call("symbolic", { bin: this.#bin, state: this.#id, action, ...extra }); }
    step(until = []) {
      const result = this.#call("step", { until: until.map(address) });
      if (result.states) result.states = result.states.map(id => new Symbolic(this.#bin, id));
      return result;
    }
    fork() { return new Symbolic(this.#bin, this.#call("fork")); }
    symbolic() { return this.#call("term"); }
    constant(value) { return this.#call("constant", { value: String(address(value)) }); }
    readRegister(index) { return this.#call("readRegister", { index }); }
    writeRegister(index, term) { this.#call("writeRegister", { index, term }); }
    readMemory(at, size) { return this.#call("readMemory", { at: String(address(at)), size }); }
    writeMemory(at, terms) { this.#call("writeMemory", { at: String(address(at)), terms }); }
    constrain(lhs, condition, rhs, bits = 64) { this.#call("constrain", { lhs, condition, rhs, bits }); }
    satisfiable() { return this.#call("satisfiable"); }
    evaluate(term, count = 1) { return this.#call("evaluate", { term, count }); }
    bounds(term) { return this.#call("bounds", { term }); }
    address() { return this.#call("address"); }
    dispose() { this.#call("dispose"); }
  }

  class Binary {
    #id;
    #functions;
    constructor({ id, ...info }) {
      this.#id = id;
      Object.assign(this, info);
    }
    decompile(functions) { return call("decompileMany", { bin: this.#id, addresses: functions?.map(f => f.addr) }); }
    classes() { return call("classes", { bin: this.#id }); }
    libraryType(name) { return call("libraryType", { bin: this.#id, name }); }
    emulate(start, options = {}) {
      if (typeof start === "number" && (!Number.isSafeInteger(start) || start < 0)) throw new RangeError("use a decimal or hex string for a 64-bit address");
      return call("emulate", { bin: this.#id, start: String(address(start)), options });
    }
    explore(start, options = {}) { return call("explore", { bin: this.#id, start: String(address(start)), options }); }
    symbolic(start, options = {}) { return new Symbolic(this.#id, call("symbolic", { bin: this.#id, action: "create", start: String(address(start)), options })); }
    saveUnpacked(path) { return call("saveUnpacked", { bin: this.#id, path }); }
    sections() { return call("sections", { bin: this.#id }); }
    compare(other, { carryAnnotations = false } = {}) {
      const result = call("compare", { first: this.#id, second: other.#id, carryAnnotations });
      if (carryAnnotations) other.#functions = undefined;
      return result;
    }
    functions({ name, named, minSize } = {}) {
      this.#functions ??= call("functions", { bin: this.#id }).map((row) => new Func(this.#id, row));
      const names = (f) => [f.name, ...f.aliases].filter((n) => n !== null);
      // A global or sticky pattern would carry its position from one name to the next.
      const pattern = name instanceof RegExp ? new RegExp(name.source, name.flags.replace(/[gy]/g, "")) : null;
      const matches = (n) => (pattern ? pattern.test(n) : n.includes(name));
      return this.#functions.filter((f) =>
        (name === undefined || names(f).some(matches)) &&
        (named === undefined || (f.name !== null) === named) &&
        (minSize === undefined || (f.size ?? 0) >= minSize));
    }
    getFunction(target) {
      if (target === "*") throw new Error("'*' is not a function selector; select a small batch with b.functions().slice(0, 5) before calling decompile()");
      try {
        return new Func(this.#id, call("find", { bin: this.#id, target: String(address(target)) }));
      } catch (error) {
        if (error.message.startsWith("no function matches") && !error.message.includes("binary is stripped")) {
          const prefix = String(target).slice(0, 3).toLowerCase();
          const candidates = this.functions().filter(f => [f.name, ...f.aliases].some(name => name?.toLowerCase().startsWith(prefix))).slice(0, 5);
          if (candidates.length) error.message += "; candidates: " + candidates.map(f => `${f.name} (${f.addr})`).join(", ");
          error.message += "; list functions with b.functions().slice(0, 10); for stripped binaries try b.entry or a listed address";
        } else if (error.message.startsWith("no function at")) {
          error.message += "; use an exact function start from b.functions().slice(0, 10), not a file offset";
        }
        throw error;
      }
    }
    projectSet(annotation) { this.#functions = undefined; return call("project", { bin: this.#id, action: "set", value: annotation }); }
    projectGet(target) { return call("project", { bin: this.#id, action: "get", value: target }); }
    projectList() { return call("project", { bin: this.#id, action: "list" }); }
    projectRemove(target) { this.#functions = undefined; return call("project", { bin: this.#id, action: "remove", value: target }); }
    projectExport() { return call("project", { bin: this.#id, action: "export" }); }
    projectImport(project) { this.#functions = undefined; return call("project", { bin: this.#id, action: "import", value: project }); }
    buildSignatures() { return call("buildSignatures", { bin: this.#id }); }
    identify(signatures) { const result = call("identify", { bin: this.#id, signatures }); this.#functions = undefined; return result; }
    xrefs(target, { from = false } = {}) { return call("navigate", { bin: this.#id, query: { kind: "xrefs", target: String(address(target)), from } }); }
    callers(target, { depth = 1 } = {}) { return call("navigate", { bin: this.#id, query: { kind: "callers", target: String(address(target)), depth } }); }
    callees(target, { depth = 1 } = {}) { return call("navigate", { bin: this.#id, query: { kind: "callees", target: String(address(target)), depth } }); }
    callPath(from, to, { depth = 32 } = {}) { return call("navigate", { bin: this.#id, query: { kind: "path", from: String(address(from)), to: String(address(to)), depth } }); }
    search(pattern, options = {}) {
      const opts = { ...options };
      for (const key of ["start", "end"]) if (opts[key] !== undefined) opts[key] = String(address(opts[key]));
      if (typeof pattern === "number" && (!Number.isSafeInteger(pattern))) throw new RangeError("use a decimal or hex string for a 64-bit search integer");
      return call("navigate", { bin: this.#id, query: { kind: "search", pattern: String(pattern), options: opts } });
    }
    readMemory(target, type, { count = 1 } = {}) { return call("navigate", { bin: this.#id, query: { kind: "readMemory", target: String(address(target)), type, count } }); }
    detectConstants() { return call("navigate", { bin: this.#id, query: { kind: "detectConstants" } }); }
    strings({ contains, decode = true } = {}) { return call("navigate", { bin: this.#id, query: { kind: "strings", contains, decode } }); }
    constants(value) {
      if (typeof value === "number" && (!Number.isSafeInteger(value) || value < 0)) throw new RangeError("use a decimal or hex string for a 64-bit constant");
      return call("navigate", { bin: this.#id, query: { kind: "constants", value: String(address(value)) } });
    }
  }

  const output = [];
  Object.defineProperty(globalThis, "__velkReset", { value: () => { output.length = 0; } });
  const show = (value) => (typeof value === "string" ? value : JSON.stringify(value) ?? String(value));
  const log = (...values) => { output.push(values.map(show).join(" ")); };

  globalThis.console = Object.freeze({ log, info: log, warn: log, error: log });
  globalThis.velk = Object.freeze({ open: (path, opts = {}) => new Binary(call("open", { path, project: opts.project, arch: opts.arch, raw: opts.raw, cache: opts.cache, signatureOptions: { defaults: opts.defaultSignatures !== false, files: opts.signatures ?? [] } })), buildSignatures: (path) => call("buildSignatures", { bin: path }) });
  globalThis.__velkStructured = (value) => {
    try { return JSON.stringify({ log: output, result: value === undefined ? null : value }); }
    catch (error) { return JSON.stringify({ log: output, error: `cannot serialize the result: ${error?.message ?? error}` }); }
  };
  // The logged output, and the result's text unless showing it fails: then
  // the failure is left in __velkFinishError and the log still returned.
  globalThis.__velkFinish = (value) => {
    if (value !== undefined) {
      try {
        output.push(show(value));
      } catch (error) {
        globalThis.__velkFinishError = `cannot show the result: ${error?.message ?? error}`;
      }
    }
    return output.join("\n");
  };
})();
