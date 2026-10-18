"use strict";
(() => {
  const native = globalThis.__velk;
  delete globalThis.__velk;
  const call = (op, args) => JSON.parse(native(op, JSON.stringify(args)));

  const normalizeAddr = (value) =>
    typeof value === "number"
      ? "0x" + value.toString(16)
      : "0x" + value.slice(2).toLowerCase().replace(/^0+(?=.)/, "");

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
    evidence() { return this.#call("evidence"); }
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
      return this.#functions.filter((f) =>
        (name === undefined ||
          (name instanceof RegExp ? name.test(f.name ?? "") : (f.name ?? "").includes(name))) &&
        (named === undefined || (f.name !== null) === named) &&
        (minSize === undefined || (f.size ?? 0) >= minSize));
    }
    getFunction(target) {
      const all = this.functions();
      if (typeof target === "number" || /^0x[0-9a-f]+$/i.test(target)) {
        const addr = normalizeAddr(target);
        const found = all.find((f) => f.addr === addr);
        if (!found) throw new Error(`no function at ${addr}`);
        return found;
      }
      const exact = all.find((f) => f.name === target);
      if (exact) return exact;
      const needle = target.toLowerCase();
      const partial = all.filter((f) => f.name?.toLowerCase().includes(needle));
      if (partial.length === 1) return partial[0];
      if (partial.length === 0) throw new Error(`no function matches "${target}"`);
      const shown = partial.slice(0, 10).map((f) => `${f.name} (${f.addr})`).join(", ");
      const more = partial.length > 10 ? ` and ${partial.length - 10} more` : "";
      throw new Error(`"${target}" is ambiguous: ${shown}${more}; pass an exact name or address`);
    }
    buildSignatures() { return call("buildSignatures", { bin: this.#id }); }
    identify(db) {
      return call("identify", typeof db === "string" ? { bin: this.#id, path: db } : { bin: this.#id, db });
    }
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
