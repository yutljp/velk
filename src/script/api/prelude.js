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
    identify(signatures) { return call("identify", { bin: this.#id, signatures }); }
  }

  const output = [];
  const show = (value) => (typeof value === "string" ? value : JSON.stringify(value) ?? String(value));
  const log = (...values) => { output.push(values.map(show).join(" ")); };

  globalThis.console = Object.freeze({ log, info: log, warn: log, error: log });
  globalThis.velk = Object.freeze({ open: (path) => new Binary(call("open", { path })) });
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
