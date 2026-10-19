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
      const matches = (n) => (name instanceof RegExp ? name.test(n) : n.includes(name));
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
  globalThis.__velkFinish = (value) => {
    if (value !== undefined) output.push(show(value));
    return output.join("\n");
  };
})();
