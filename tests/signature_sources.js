// Compare fixture databases with independent function names.
const results = [];
const originalNames = new Map();
function check(database, source, target, kind) {
    const reference = velk.open(`tests/fixtures/${source}`).functions();
    const binary = velk.open(`tests/fixtures/${target}`);
    const expected = new Map(reference.map(f => [f.addr, [f.name, ...f.aliases]]));
    const before = originalNames.get(target) ?? new Map(binary.functions().map(f => [f.addr, f.name]));
    originalNames.set(target, before);
    const matches = binary.identify(database).matches;
    const wrong = matches.filter(m => !(expected.get(m.addr) ?? []).includes(m.matched));
    results.push({
        kind, target, functions: before.size, matches: matches.length,
        renamed: matches.filter(m => before.get(m.addr) === null).length,
        falsePositives: wrong.length,
    });
    if (wrong.length) throw Error(JSON.stringify({ target, wrong }));
}

for (const [source, target] of [
    ["rust_probe", "rust_probe_stripped"],
    ["rust_probe_arm64", "rust_probe_arm64_stripped"],
    ["x64_loops.o", "x64_loops_stripped.o"],
    ["arm64_loops.o", "arm64_loops_stripped.o"],
    ["arm64_debug.elf", "arm64_debug_stripped.elf"],
    ["tail_calls.o", "tail_calls_stripped.o"],
    ["tail_indirect.o", "tail_indirect_stripped.o"],
    ["cold_gcc", "cold_gcc_stripped"],
]) {
    check("tests/out/signatures/libraries.json", source, target, "libraries");
}

for (const [source, target] of [
    ["go_probe", "go_stripped"],
    ["go_probe_arm64", "go_stripped_arm64"],
]) {
    // Go runtime metadata supplies names for the stripped build itself.
    check(velk.buildSignatures(`tests/fixtures/${source}`).database, target, target, "go-runtime");
}
for (const [source, target] of [
    ["rust_probe", "rust_probe_stripped"],
    ["rust_probe_arm64", "rust_probe_arm64_stripped"],
    ["x64_loops.o", "x64_loops_stripped.o"],
    ["arm64_loops.o", "arm64_loops_stripped.o"],
    ["arm64_debug.elf", "arm64_debug_stripped.elf"],
    ["tail_calls.o", "tail_calls_stripped.o"],
    ["tail_indirect.o", "tail_indirect_stripped.o"],
    ["cold_gcc", "cold_gcc_stripped"],
]) {
    check(velk.buildSignatures(`tests/fixtures/${source}`).database, source, target, "fixture-control");
}
console.log(JSON.stringify(results, null, 2));
