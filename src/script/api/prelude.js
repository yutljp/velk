"use strict";
(() => {
  const native = globalThis.__velk;
  delete globalThis.__velk;
  const call = (op, args) => JSON.parse(native(JSON.stringify({ op, ...args })));
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
    card({ budget } = {}) { return this.#call("card", { budget }); }
    decompile() { return this.#call("decompile"); }
    disasm({ limit } = {}) { return this.#call("disasm", { limit }); }
    ir() { return this.#call("ir"); }
    signature() { return this.#call("signature"); }
    references() { return this.#call("references"); }
    strings() { return this.#call("strings"); }
    shapeHash() { return this.#call("shapeHash"); }
    summary() { return call("navigate", { bin: this.#bin, query: { kind: "summary", target: this.addr } }); }
    xrefs({ from = false } = {}) { return call("navigate", { bin: this.#bin, query: { kind: "xrefs", target: this.addr, from } }); }
    callers({ depth = 1 } = {}) { return call("navigate", { bin: this.#bin, query: { kind: "callers", target: this.addr, depth } }); }
    callees({ depth = 1 } = {}) { return call("navigate", { bin: this.#bin, query: { kind: "callees", target: this.addr, depth } }); }
  }

  class Binary {
    #id;
    #functions;
    constructor({ id, ...info }) {
      this.#id = id;
      Object.assign(this, info);
    }
    sections() { return call("sections", { bin: this.#id }); }
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
      return new Func(this.#id, call("find", { bin: this.#id, target: String(address(target)) }));
    }
    buildSignatures() { return call("buildSignatures", { bin: this.#id }); }
    identify(signatures) { const result = call("identify", { bin: this.#id, signatures }); this.#functions = undefined; return result; }
    xrefs(target, { from = false } = {}) { return call("navigate", { bin: this.#id, query: { kind: "xrefs", target: String(address(target)), from } }); }
    callers(target, { depth = 1 } = {}) { return call("navigate", { bin: this.#id, query: { kind: "callers", target: String(address(target)), depth } }); }
    callees(target, { depth = 1 } = {}) { return call("navigate", { bin: this.#id, query: { kind: "callees", target: String(address(target)), depth } }); }
    callPath(from, to, { depth = 32 } = {}) { return call("navigate", { bin: this.#id, query: { kind: "path", from: String(address(from)), to: String(address(to)), depth } }); }
    strings({ contains } = {}) { return call("navigate", { bin: this.#id, query: { kind: "strings", contains } }); }
    constants(value) {
      if (typeof value === "number" && (!Number.isSafeInteger(value) || value < 0)) throw new RangeError("use a decimal or hex string for a 64-bit constant");
      return call("navigate", { bin: this.#id, query: { kind: "constants", value: String(address(value)) } });
    }
  }

  const output = [];
  const show = (value) => (typeof value === "string" ? value : JSON.stringify(value) ?? String(value));
  const log = (...values) => { output.push(values.map(show).join(" ")); };

  globalThis.console = Object.freeze({ log, info: log, warn: log, error: log });
  globalThis.velk = Object.freeze({ open: (path) => new Binary(call("open", { path })), buildSignatures: (path) => call("buildSignatures", { bin: path }) });
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
