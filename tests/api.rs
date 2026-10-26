//! The script API matches its TypeScript declarations in src/script/api/:
//! every declared method runs, every returned object carries the declared
//! fields, and nothing undeclared.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use velk::script::Engine;

#[test]
fn macho_lookup_accepts_c_and_link_names() {
    let path = common::fixtures_dir().join("arm64_macho.o");
    let script = format!(
        r#"
const b = velk.open({path:?});
const link = b.getFunction("_sum3");
const c = b.getFunction("sum3");
JSON.stringify([link.name, c.name, link.decompile(), c.decompile(), c.card().name])
"#,
        path = path.display().to_string()
    );
    let outcome = Engine::new().unwrap().run(&script, None);
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
    let values: Vec<String> = serde_json::from_str(&outcome.output).unwrap();
    assert_eq!(values[0], "_sum3");
    assert_eq!(values[1], "_sum3");
    assert_eq!(values[2], values[3]);
    assert_eq!(values[4], "_sum3");
    assert!(values[2].contains("sum3(int32_t"), "{}", values[2]);
}

/// Field names per interface, split into required and optional (`name?:`).
fn declarations() -> BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> {
    let mut interfaces = BTreeMap::new();
    for file in ["binary.d.ts", "func.d.ts", "types.d.ts", "emulation.d.ts"] {
        let path = common::root().join("src/script/api").join(file);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let mut current: Option<(String, BTreeSet<String>, BTreeSet<String>)> = None;
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("interface ") {
                let name = rest.trim_end_matches('{').trim().to_owned();
                current = Some((name, BTreeSet::new(), BTreeSet::new()));
            } else if line == "}" {
                if let Some((name, required, optional)) = current.take() {
                    interfaces.insert(name, (required, optional));
                }
            } else if let Some((_, required, optional)) = current.as_mut() {
                // A field is `name: type;` or `name?: type;`; methods have parentheses before the colon.
                let Some((name, _)) = line.split_once(':') else {
                    continue;
                };
                if line.starts_with("/*") || line.starts_with('*') || name.contains('(') {
                    continue;
                }
                match name.strip_suffix('?') {
                    Some(name) => optional.insert(name.to_owned()),
                    None => required.insert(name.to_owned()),
                };
            }
        }
    }
    interfaces
}

/// Runs every declared method on one fixture and returns the results as JSON.
fn exercise(fixture: &str, function: &str) -> Value {
    let path = common::fixtures_dir().join(fixture);
    let script = format!(
        r#"
const b = velk.open({path:?});
const f = b.getFunction({function:?});
const signatures = b.buildSignatures();
JSON.stringify({{
  binary: {{ path: b.path, format: b.format, arch: b.arch, entry: b.entry, slices: b.slices, sliceOffset: b.sliceOffset }},
  section: b.sections()[0],
  func: Object.fromEntries(Object.entries(f)),
  card: f.card(),
  smallCard: f.card({{ budget: 100 }}),
  decompile: f.decompile(),
  disasm: f.disasm({{ limit: 3 }}),
  ir: f.ir(),
  execution: b.emulate(f.addr, {{end: [f.addr]}}),
  functionExecution: f.emulate({{end: [f.addr]}}),
  signature: f.signature(),
  references: f.references(),
  strings: f.strings(),
  shapeHash: f.shapeHash(),
  navigation: {{
    xrefs: b.xrefs(f.addr),
    callers: b.callers(f.addr),
    callees: b.callees(f.addr),
    path: b.callPath(f.addr, f.addr, {{ depth: 0 }}),
    constants: b.constants("0x1"),
    byteSearch: b.search("00"),
    memoryRead: b.readMemory(f.addr, "u8"),
    detectedConstants: b.detectConstants(),
    strings: b.strings(),
    summary: f.summary(),
    functionXrefs: f.xrefs(),
    functionCallers: f.callers(),
    functionCallees: f.callees(),
  }},
  signatures,
  identify: b.identify(signatures.database),
  comparison: b.compare(b),
  functionCount: b.functions().length,
  namedOnly: b.functions({{ named: true }}).every((g) => g.name !== null),
  byRegExp: b.functions({{ name: /^{function}$/ }}).length,
}})
"#,
        path = path.display().to_string(),
    );
    let outcome = Engine::new()
        .unwrap_or_else(|error| panic!("{error}"))
        .run(&script, None);
    if let Some(error) = outcome.error {
        panic!("{fixture}: {error}");
    }
    serde_json::from_str(&outcome.output)
        .unwrap_or_else(|error| panic!("{fixture}: {error}: {}", outcome.output))
}

fn check(
    interfaces: &BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)>,
    interface: &str,
    value: &Value,
    at: &str,
) -> Vec<String> {
    let (required, optional) = interfaces
        .get(interface)
        .unwrap_or_else(|| panic!("no interface {interface} in the declarations"));
    let Some(object) = value.as_object() else {
        return vec![format!(
            "{at}: expected an object for {interface}, got {value}"
        )];
    };
    let mut problems = Vec::new();
    for field in required {
        if !object.contains_key(field) {
            problems.push(format!("{at}: {interface}.{field} is missing"));
        }
    }
    for field in object.keys() {
        if !required.contains(field) && !optional.contains(field) {
            problems.push(format!("{at}: {interface}.{field} is not declared"));
        }
    }
    problems
}

#[test]
fn script_results_match_the_declarations() {
    let interfaces = declarations();
    let cases = [
        ("arm64.o", "pair_sum"),
        ("x64_div.o", "smod3x"),
        ("arm64_linked.elf", "pick"),
    ];
    let mut problems = Vec::new();
    for (fixture, function) in cases {
        let result = exercise(fixture, function);
        let at = |field: &str| format!("{fixture} {function} {field}");
        problems.extend(check(
            &interfaces,
            "Section",
            &result["section"],
            &at("sections()[0]"),
        ));
        problems.extend(check(&interfaces, "Card", &result["card"], &at("card()")));
        for field in ["execution", "functionExecution"] {
            problems.extend(check(
                &interfaces,
                "EmulationReport",
                &result[field],
                &at(field),
            ));
            assert_eq!(result[field]["reason"], "end address");
            assert_eq!(result[field]["steps"], 0);
        }

        let navigation = &result["navigation"];
        for (field, interface) in [
            ("xrefs", "XrefResult"),
            ("callers", "GraphResult"),
            ("callees", "GraphResult"),
            ("path", "PathResult"),
            ("constants", "ConstantsResult"),
            ("byteSearch", "ByteSearchResult"),
            ("memoryRead", "MemoryReadResult"),
            ("detectedConstants", "DetectedConstantsResult"),
            ("strings", "StringsResult"),
            ("summary", "FunctionSummary"),
            ("functionXrefs", "XrefResult"),
            ("functionCallers", "GraphResult"),
            ("functionCallees", "GraphResult"),
        ] {
            problems.extend(check(
                &interfaces,
                interface,
                &navigation[field],
                &at(field),
            ));
        }
        for (field, array, interface) in [
            ("xrefs", "xrefs", "Xref"),
            ("constants", "matches", "ConstantMatch"),
            ("byteSearch", "matches", "ByteSearchMatch"),
            ("detectedConstants", "matches", "DetectedConstant"),
            ("strings", "strings", "StringLiteral"),
        ] {
            for value in navigation[field][array].as_array().into_iter().flatten() {
                problems.extend(check(&interfaces, interface, value, &at(field)));
            }
        }
        assert_eq!(
            navigation["path"]["path"],
            serde_json::json!([result["func"]["addr"]])
        );
        problems.extend(check(
            &interfaces,
            "Card",
            &result["smallCard"],
            &at("card({budget: 100})"),
        ));
        problems.extend(check(
            &interfaces,
            "Signature",
            &result["signature"],
            &at("signature()"),
        ));
        problems.extend(check(
            &interfaces,
            "SignatureDb",
            &result["signatures"]["database"],
            &at("buildSignatures().database"),
        ));
        for (index, reference) in result["references"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            problems.extend(check(
                &interfaces,
                "Reference",
                reference,
                &at(&format!("references()[{index}]")),
            ));
        }
        for (index, hit) in result["identify"]["matches"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            problems.extend(check(
                &interfaces,
                "Match",
                hit,
                &at(&format!("identify().matches[{index}]")),
            ));
        }

        // The data fields of Binary and Func, without their methods.
        let fields = |interface: &str| {
            let (required, optional) = &interfaces[interface];
            (required.clone(), optional.clone())
        };
        let (binary_fields, _) = fields("Binary");
        for field in binary_fields {
            if result["binary"].get(&field).is_none() {
                problems.push(at(&format!("Binary.{field} is missing")));
            }
        }
        let (func_required, func_optional) = fields("Func");
        for field in func_required.iter() {
            if result["func"].get(field).is_none() {
                problems.push(at(&format!("Func.{field} is missing")));
            }
        }
        for field in result["func"]
            .as_object()
            .into_iter()
            .flat_map(|object| object.keys())
        {
            if !func_required.contains(field) && !func_optional.contains(field) {
                problems.push(at(&format!("Func.{field} is not declared")));
            }
        }

        for (field, kind) in [
            ("decompile", "string"),
            ("ir", "string"),
            ("shapeHash", "string"),
        ] {
            if !result[field].is_string() {
                problems.push(at(&format!("{field}() should return a {kind}")));
            }
        }
        for field in ["disasm", "strings"] {
            if !result[field].is_array() {
                problems.push(at(&format!("{field}() should return an array")));
            }
        }
        if result["disasm"]
            .as_array()
            .is_some_and(|lines| lines.len() > 3)
        {
            problems.push(at("disasm({limit: 3}) returned more than 3 lines"));
        }
        if result["smallCard"]["approxTokens"]
            .as_u64()
            .is_some_and(|tokens| tokens > 100)
        {
            problems.push(at("card({budget: 100}) is over its budget"));
        }
        if result["namedOnly"] != Value::Bool(true) {
            problems.push(at("functions({named: true}) returned an unnamed function"));
        }
        if result["byRegExp"] != 1 {
            problems.push(at(
                "functions({name: RegExp}) did not find exactly the function",
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "the API and its declarations disagree:\n{}",
        problems.join("\n")
    );
}

#[test]
fn every_declared_method_is_exercised() {
    let source =
        std::fs::read_to_string(common::root().join("tests/api.rs")).expect("reading this test");
    let mut missing = Vec::new();
    for file in ["binary.d.ts", "func.d.ts"] {
        let text = std::fs::read_to_string(common::root().join("src/script/api").join(file))
            .expect("reading the declarations");
        for line in text.lines() {
            let line = line.trim();
            let Some((name, _)) = line.split_once('(') else {
                continue;
            };
            if line.starts_with("/*")
                || line.starts_with('*')
                || line.starts_with("//")
                || name.contains([' ', ':'])
            {
                continue;
            }
            if !source.contains(&format!(".{name}(")) {
                missing.push(name.to_owned());
            }
        }
    }
    assert!(
        missing.is_empty(),
        "declared but not exercised: {missing:?}"
    );
}

/// A global pattern matches each name on its own, as a plain one does.
#[test]
fn a_global_pattern_finds_every_matching_function() {
    let path = common::fixtures_dir().join("arm64.o");
    let engine = Engine::new().expect("an engine");
    let outcome = engine.run(
        &format!(
            "const b = velk.open({path:?}); \
             [b.functions({{ name: /^./ }}).length, b.functions({{ name: /^./g }}).length].join(' ')"
        ),
        None,
    );
    assert_eq!(outcome.error, None);
    let counts: Vec<&str> = outcome.output.split(' ').collect();
    assert_eq!(counts[0], counts[1], "{}", outcome.output);
}

/// A result the output cannot show is an error, and what was logged before
/// it stays.
#[test]
fn a_result_that_cannot_be_shown_is_an_error() {
    let engine = Engine::new().expect("an engine");
    let outcome = engine.run("console.log('before'); 1n", None);
    assert!(outcome.error.is_some(), "{:?}", outcome.output);
    assert!(outcome.output.contains("before"), "{:?}", outcome.output);
}

/// The time allowed stops repeated operations over the whole binary too.
/// A single instruction-signature build can finish before the deadline.
#[test]
fn a_timeout_stops_an_operation_over_the_binary() {
    let path = common::fixtures_dir().join("go_probe");
    let engine = Engine::new().expect("an engine");
    let started = std::time::Instant::now();
    let outcome = engine.run(
        &format!("const b = velk.open({path:?}); while (true) b.buildSignatures();"),
        Some(std::time::Duration::from_millis(500)),
    );
    assert!(outcome.error.is_some(), "{:?}", outcome.output);
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}

#[test]
fn a_timeout_stops_one_function_analysis() {
    let path = common::fixtures_dir().join("go_probe");
    let script = format!("velk.open({path:?}).getFunction('main.main').decompile()");
    let open = format!("velk.open({path:?}); null");
    let unlimited_engine = Engine::new().expect("an engine");
    assert_eq!(unlimited_engine.run(&open, None).error, None);
    let started = std::time::Instant::now();
    let unlimited = unlimited_engine.run(&script, None);
    let unlimited_time = started.elapsed();
    assert_eq!(unlimited.error, None);
    assert!(unlimited.output.contains("main"), "{}", unlimited.output);

    let engine = Engine::new().expect("an engine");
    assert_eq!(engine.run(&open, None).error, None);
    let started = std::time::Instant::now();
    let limited = engine.run(&script, Some(std::time::Duration::from_millis(100)));
    let limited_time = started.elapsed();
    eprintln!("function decompilation: limited={limited_time:?}, unlimited={unlimited_time:?}");
    assert!(
        limited
            .error
            .as_deref()
            .is_some_and(|error| error.contains("timed out")),
        "{:?}",
        limited.error
    );
    let retry = engine.run(&script, None);
    assert_eq!(retry.error, None);
    assert_eq!(retry.output, unlimited.output);
}

#[test]
fn batch_decompilation_prints_one_prelude() {
    let path = common::fixtures_dir().join("arm64.o");
    let script = format!(
        "const b = velk.open({:?}); for (const f of b.functions()) console.log(f.decompile());",
        path.display().to_string()
    );
    let outcome = Engine::new().unwrap().run(&script, None);
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
    assert!(outcome.output.starts_with("/* velk prelude */\n"));
    assert_eq!(outcome.output.matches("/* velk prelude */").count(), 1);
    assert_eq!(
        outcome
            .output
            .matches("static inline uint64_t add_lanes32")
            .count(),
        1
    );
    let end = outcome.output.find("/* end velk prelude */").unwrap();
    assert!(end < outcome.output.find("/* velk pseudo-C:").unwrap());
}

#[test]
fn project_methods_persist_and_apply_annotations() {
    let directory = common::root()
        .join("target")
        .join(format!("api-project-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("app.o");
    std::fs::copy(common::fixtures_dir().join("arm64.o"), &path).unwrap();
    let script = format!(
        r#"
const b = velk.open({path:?}, {{project: {project:?}}});
const f = b.getFunction("sum3");
const target = {{kind:"function", address:f.addr}};
b.projectSet({{target, name:"sum_values"}});
if (b.projectGet(target).name !== "sum_values") throw Error("get");
if (b.projectList().length !== 1) throw Error("list");
const exported = b.projectExport();
b.projectRemove(target);
b.projectImport(exported);
if (b.getFunction("sum_values").name !== "sum_values") throw Error("name");
const parameter = f.origins().find(row => row.target.kind === "parameter");
b.projectSet({{target:parameter.target, name:"first"}});
if (!f.decompile().includes("int32_t first")) throw Error("applied parameter");
if (f.signature().params[0].name !== "first") throw Error("applied signature metadata");
try {{ b.projectSet({{target, name:"int"}}); throw Error("accepted keyword"); }}
catch (error) {{ if (error.code !== "invalid_identifier") throw error; }}
"#,
        path = path.to_str().unwrap(),
        project = directory.join("annotations.json").to_str().unwrap()
    );
    let outcome = Engine::new().unwrap().run(&script, None);
    assert!(!velk::project::path(&path).exists());
    assert!(directory.join("annotations.json").exists());
    let _ = std::fs::remove_dir_all(directory);
    assert!(outcome.error.is_none(), "{:?}", outcome.error);
}

#[test]
fn class_results_match_the_declarations() {
    let interfaces = declarations();
    let mut problems = Vec::new();
    for format in ["elf", "dll", "dylib"] {
        let path = common::fixtures_dir().join(format!("cpp/rtti.stripped.{format}"));
        let outcome = Engine::new()
            .unwrap()
            .run(&format!("velk.open({path:?}).classes()"), None);
        assert!(outcome.error.is_none(), "{:?}", outcome.error);
        let classes: Vec<Value> = serde_json::from_str(&outcome.output).unwrap();
        assert_eq!(classes.len(), 6);
        for class in classes {
            problems.extend(check(&interfaces, "CppClass", &class, format));
            for base in class["bases"].as_array().unwrap() {
                problems.extend(check(&interfaces, "CppBase", base, format));
                if !base["vbtable"].is_null() {
                    problems.extend(check(
                        &interfaces,
                        "CppVirtualBase",
                        &base["vbtable"],
                        format,
                    ));
                }
            }
            for table in class["vtables"].as_array().unwrap() {
                problems.extend(check(&interfaces, "CppVtable", table, format));
                for method in table["methods"].as_array().unwrap() {
                    problems.extend(check(&interfaces, "CppMethod", method, format));
                }
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
