//! Recovery accuracy against debug information. Each case in tests/fixtures/metrics
//! comes as `*.debug.elf` / `*.debug.dll` (DWARF, the ground truth) and a stripped copy
//! (neither, what velk analyzes). The scores and per-function results are kept in
//! tests/golden/metrics.txt; any change fails until blessed with `VELK_BLESS=1`.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::path::Path;

use gimli::{AttributeValue, EndianSlice, LittleEndian};
use object::{Object, ObjectSection, ObjectSymbol};
use velk::ir::CType;
use velk::service::Binary;

#[derive(Debug, Clone, PartialEq)]
enum Kind {
    Void,
    Pointer,
    Scalar {
        bytes: u64,
        signed: bool,
    },
    Float {
        bytes: u64,
    },
    /// Structures, unions and arrays, which the ABI passes differently.
    Other,
}

struct Truth {
    name: String,
    params: Vec<Kind>,
    variadic: bool,
    ret: Kind,
}

#[derive(Default)]
struct Score {
    correct: usize,
    total: usize,
}

impl Score {
    fn add(&mut self, correct: bool) {
        self.total += 1;
        self.correct += usize::from(correct);
    }
}

const METRICS: [&str; 9] = [
    "functions found",
    "extra functions",
    "parameter count",
    "parameter pointer",
    "parameter width",
    "parameter sign",
    "return void",
    "return width",
    "float type",
];

#[test]
fn recovery_metrics_match_the_recorded_scores() {
    let dir = common::fixtures_dir().join("metrics");
    let mut cases: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
        .filter_map(|entry| {
            let Ok(entry) = entry else { return None };
            let Ok(name) = entry.file_name().into_string() else {
                return None;
            };
            name.strip_suffix(".debug.elf")
                .or_else(|| name.strip_suffix(".debug.dll"))
                .map(str::to_owned)
        })
        .collect();
    cases.sort();
    assert!(
        !cases.is_empty(),
        "no metrics fixtures in {}",
        dir.display()
    );

    let results = common::in_parallel(&cases, |case| measure(&dir, case));
    let mut totals: BTreeMap<(String, &str), Score> = BTreeMap::new();
    let mut details = String::new();
    for (case, (scores, lines)) in cases.iter().zip(results) {
        let config = case
            .split_once('.')
            .map_or(case.as_str(), |(_, config)| config)
            .to_owned();
        for (metric, score) in scores {
            let total = totals.entry((config.clone(), metric)).or_default();
            total.correct += score.correct;
            total.total += score.total;
        }
        for line in lines {
            writeln!(details, "{case} {line}").expect("writing to a String");
        }
    }
    let mut actual = String::from("# metric | config | correct/total\n");
    for metric in METRICS {
        for ((config, name), score) in &totals {
            if *name == metric {
                writeln!(
                    actual,
                    "{metric} | {config} | {}/{}",
                    score.correct, score.total
                )
                .expect("writing to a String");
            }
        }
    }
    actual.push('\n');
    actual.push_str(&details);

    let expected_path = common::root().join("tests/golden/metrics.txt");
    let summary_before = std::fs::read_to_string(&expected_path).unwrap_or_default();
    if let Some(difference) = common::check_expected(&expected_path, &actual) {
        panic!(
            "recovery results changed:\n{}\nfirst difference: {difference}\nbless with VELK_BLESS=1 once the change is understood",
            summary_changes(&summary_before, &actual)
        );
    }
}

/// The summary lines whose scores differ, marked as improved or regressed.
fn summary_changes(before: &str, after: &str) -> String {
    let scores = |text: &str| -> HashMap<String, (usize, usize)> {
        text.lines()
            .take_while(|line| !line.is_empty())
            .filter_map(|line| {
                let (key, score) = line.rsplit_once(" | ")?;
                let (correct, total) = score.split_once('/')?;
                Some((key.to_owned(), (correct.parse().ok()?, total.parse().ok()?)))
            })
            .collect()
    };
    let (before, after) = (scores(before), scores(after));
    let mut keys: Vec<&String> = before.keys().chain(after.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut out = String::new();
    for key in keys {
        let old = before.get(key).copied().unwrap_or((0, 0));
        let new = after.get(key).copied().unwrap_or((0, 0));
        if old != new {
            // Only a score over the same set of cases says better or worse.
            let better = if key.starts_with("extra") {
                new.0 < old.0
            } else {
                new.0 > old.0
            };
            let direction = if old.1 != new.1 {
                "changed"
            } else if better {
                "improved"
            } else {
                "regressed"
            };
            writeln!(
                out,
                "  {direction}: {key} {}/{} -> {}/{}",
                old.0, old.1, new.0, new.1
            )
            .expect("writing to a String");
        }
    }
    if out.is_empty() {
        out.push_str("  scores unchanged; only per-function details differ\n");
    }
    out
}

fn measure(dir: &Path, case: &str) -> (Vec<(&'static str, Score)>, Vec<String>) {
    let extension = if case.contains(".win64.") || case.contains(".win32.") {
        "dll"
    } else {
        "elf"
    };
    let truth = truth(&dir.join(format!("{case}.debug.{extension}")));
    assert!(!truth.is_empty(), "{case}: no DWARF functions");
    let mut binary = Binary::open(&dir.join(format!("{case}.stripped.{extension}")))
        .unwrap_or_else(|error| panic!("{error}"));
    let found: Vec<u64> = binary.image().functions.keys().copied().collect();

    let mut scores: BTreeMap<&'static str, Score> = METRICS
        .iter()
        .map(|metric| (*metric, Score::default()))
        .collect();
    let mut lines = Vec::new();
    for addr in &found {
        let extra = !truth.contains_key(addr);
        scores
            .get_mut("extra functions")
            .expect("known metric")
            .add(extra);
        if extra {
            lines.push(format!("{} extra function", velk::addr::format(*addr)));
        }
    }
    for (addr, expected) in &truth {
        let label = format!("{} {}", velk::addr::format(*addr), expected.name);
        let present = found.contains(addr);
        scores
            .get_mut("functions found")
            .expect("known metric")
            .add(present);
        if !present {
            lines.push(format!("{label}: not found"));
            continue;
        }
        let Ok(analysis) = binary.analysis(*addr, None) else {
            lines.push(format!("{label}: lift failed"));
            continue;
        };
        let ir = &analysis.ir;
        // Parameters in the caller's frame take their places among the
        // register ones. The pointer a structure is returned through is no
        // parameter of the source.
        let named: Vec<_> = ir
            .params
            .iter()
            .filter(|param| param.name != "result")
            .collect();
        let mut registers = named.iter().copied();
        let got_params: Vec<Kind> = (0..named.len() + ir.stack_params.len())
            .filter_map(|position| {
                match ir
                    .stack_params
                    .iter()
                    .find(|param| param.position == position)
                {
                    Some(param) => Some(&param.ty),
                    None => registers.next().map(|param| &param.ty),
                }
            })
            .map(kind_of)
            .collect();
        let got_ret = kind_of(&ir.ret_type);
        let mut mismatches = Vec::new();
        if !expected.variadic {
            let count_ok = got_params.len() == expected.params.len();
            scores
                .get_mut("parameter count")
                .expect("known metric")
                .add(count_ok);
            if !count_ok {
                mismatches.push(format!(
                    "{} parameters, expected {}",
                    got_params.len(),
                    expected.params.len()
                ));
            }
            if count_ok {
                for (index, (want, got)) in expected.params.iter().zip(&got_params).enumerate() {
                    compare_kind(&mut scores, "parameter", index, want, got, &mut mismatches);
                }
            }
        }
        let void_ok = (expected.ret == Kind::Void) == (got_ret == Kind::Void);
        scores
            .get_mut("return void")
            .expect("known metric")
            .add(void_ok);
        if !void_ok {
            mismatches.push(format!(
                "returns {}, expected {}",
                ir.ret_type,
                describe(&expected.ret)
            ));
        }
        if matches!(expected.ret, Kind::Float { .. }) || matches!(got_ret, Kind::Float { .. }) {
            let float_ok = expected.ret == got_ret;
            scores
                .get_mut("float type")
                .expect("known metric")
                .add(float_ok);
            if !float_ok {
                mismatches.push(format!(
                    "returns {}, expected {}",
                    ir.ret_type,
                    describe(&expected.ret)
                ));
            }
        }
        if let (Kind::Scalar { bytes: want, .. }, Kind::Scalar { bytes: got, .. }) =
            (&expected.ret, &got_ret)
        {
            scores
                .get_mut("return width")
                .expect("known metric")
                .add(want == got);
            if want != got {
                mismatches.push(format!("returns {got} bytes, expected {want}"));
            }
        }
        lines.push(if mismatches.is_empty() {
            format!("{label}: ok")
        } else {
            format!("{label}: {}", mismatches.join("; "))
        });
    }
    (scores.into_iter().collect(), lines)
}

fn compare_kind(
    scores: &mut BTreeMap<&'static str, Score>,
    what: &str,
    index: usize,
    want: &Kind,
    got: &Kind,
    mismatches: &mut Vec<String>,
) {
    if *want == Kind::Other {
        return;
    }
    if matches!(want, Kind::Float { .. }) || matches!(got, Kind::Float { .. }) {
        scores
            .get_mut("float type")
            .expect("known metric")
            .add(want == got);
        if want != got {
            mismatches.push(format!(
                "{what} {index} is {}, expected {}",
                describe(got),
                describe(want)
            ));
        }
        return;
    }
    let pointer_ok = (*want == Kind::Pointer) == (*got == Kind::Pointer);
    scores
        .get_mut("parameter pointer")
        .expect("known metric")
        .add(pointer_ok);
    if !pointer_ok {
        mismatches.push(format!(
            "{what} {index} is {}, expected {}",
            describe(got),
            describe(want)
        ));
        return;
    }
    if let (
        Kind::Scalar {
            bytes: want_bytes,
            signed: want_signed,
        },
        Kind::Scalar { bytes, signed },
    ) = (want, got)
    {
        scores
            .get_mut("parameter width")
            .expect("known metric")
            .add(want_bytes == bytes);
        if want_bytes != bytes {
            mismatches.push(format!(
                "{what} {index} is {bytes} bytes, expected {want_bytes}"
            ));
            return;
        }
        scores
            .get_mut("parameter sign")
            .expect("known metric")
            .add(want_signed == signed);
        if want_signed != signed {
            mismatches.push(format!("{what} {index} signedness differs"));
        }
    }
}

fn describe(kind: &Kind) -> String {
    match kind {
        Kind::Void => "void".to_owned(),
        Kind::Pointer => "a pointer".to_owned(),
        Kind::Scalar { bytes, signed } => format!(
            "{} {bytes}-byte integer",
            if *signed { "a signed" } else { "an unsigned" }
        ),
        Kind::Float { bytes } => format!("a {bytes}-byte float"),
        Kind::Other => "an aggregate".to_owned(),
    }
}

fn kind_of(ty: &CType) -> Kind {
    match ty {
        CType::Void => Kind::Void,
        CType::Pointer(_) => Kind::Pointer,
        CType::Int { bytes, signed } => Kind::Scalar {
            bytes: u64::from(*bytes),
            signed: *signed,
        },
        CType::Named(name) if name == "double" => Kind::Float { bytes: 8 },
        CType::Named(name) if name == "float" => Kind::Float { bytes: 4 },
        CType::Array(_) | CType::Named(_) | CType::Function { .. } => Kind::Other,
    }
}

type Slice<'a> = EndianSlice<'a, LittleEndian>;

/// Functions with a symbol and a DWARF description, by address.
fn truth(path: &Path) -> BTreeMap<u64, Truth> {
    let data = std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let file =
        object::File::parse(&*data).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let symbols: HashMap<u64, String> = file
        .symbols()
        .filter(|symbol| symbol.kind() == object::SymbolKind::Text && symbol.size() > 0)
        .filter_map(|symbol| {
            let Ok(name) = symbol.name() else { return None };
            Some((symbol.address(), name.to_owned()))
        })
        .collect();
    let dwarf = gimli::Dwarf::load(|id| -> Result<Slice<'_>, gimli::Error> {
        let bytes = file
            .section_by_name(id.name())
            .and_then(|section| section.data().ok())
            .unwrap_or(&[]);
        Ok(EndianSlice::new(bytes, LittleEndian))
    })
    .unwrap_or_else(|error| panic!("{}: {error}", path.display()));

    let mut found = BTreeMap::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next().unwrap_or_else(|error| panic!("{error}")) {
        let unit = dwarf.unit(header).unwrap_or_else(|error| panic!("{error}"));
        let mut tree = unit
            .entries_tree(None)
            .unwrap_or_else(|error| panic!("{error}"));
        let root = tree.root().unwrap_or_else(|error| panic!("{error}"));
        let mut functions = root.children();
        while let Some(node) = functions.next().unwrap_or_else(|error| panic!("{error}")) {
            let entry = node.entry();
            if entry.tag() != gimli::DW_TAG_subprogram {
                continue;
            }
            let addr = entry
                .attr_value(gimli::DW_AT_low_pc)
                .and_then(|low| dwarf.attr_address(&unit, low).ok().flatten());
            let Some(addr) = addr else { continue };
            let name = symbols.get(&addr).cloned().or_else(|| {
                let Some(value) = entry.attr_value(gimli::DW_AT_name) else {
                    return None;
                };
                let Ok(name) = dwarf.attr_string(&unit, value) else {
                    return None;
                };
                Some(name.to_string_lossy().into_owned())
            });
            let Some(name) = name else { continue };
            let ret = type_kind(&unit, entry.attr_value(gimli::DW_AT_type));
            let mut params = Vec::new();
            let mut variadic = false;
            let mut children = node.children();
            while let Some(child) = children.next().unwrap_or_else(|error| panic!("{error}")) {
                match child.entry().tag() {
                    gimli::DW_TAG_formal_parameter => {
                        params.push(type_kind(
                            &unit,
                            child.entry().attr_value(gimli::DW_AT_type),
                        ));
                    }
                    gimli::DW_TAG_unspecified_parameters => variadic = true,
                    _ => {}
                }
            }
            found.insert(
                addr,
                Truth {
                    name,
                    params,
                    variadic,
                    ret,
                },
            );
        }
    }
    found
}

fn type_kind(unit: &gimli::Unit<Slice<'_>>, value: Option<AttributeValue<Slice<'_>>>) -> Kind {
    let Some(AttributeValue::UnitRef(mut offset)) = value else {
        return Kind::Void;
    };
    loop {
        let entry = unit.entry(offset).unwrap_or_else(|error| panic!("{error}"));
        let next = || match entry.attr_value(gimli::DW_AT_type) {
            Some(AttributeValue::UnitRef(inner)) => Some(inner),
            _ => None,
        };
        match entry.tag() {
            gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type => match next() {
                Some(inner) => offset = inner,
                None => return Kind::Void,
            },
            gimli::DW_TAG_pointer_type | gimli::DW_TAG_reference_type => return Kind::Pointer,
            gimli::DW_TAG_base_type | gimli::DW_TAG_enumeration_type => {
                let bytes = entry
                    .attr_value(gimli::DW_AT_byte_size)
                    .and_then(|value| value.udata_value())
                    .unwrap_or(0);
                let encoding = entry.attr_value(gimli::DW_AT_encoding);
                return match encoding {
                    Some(AttributeValue::Encoding(gimli::DW_ATE_float)) if bytes <= 8 => {
                        Kind::Float { bytes }
                    }
                    Some(AttributeValue::Encoding(gimli::DW_ATE_float)) => Kind::Other,
                    Some(AttributeValue::Encoding(
                        gimli::DW_ATE_signed | gimli::DW_ATE_signed_char,
                    )) => Kind::Scalar {
                        bytes,
                        signed: true,
                    },
                    // An enumeration without an encoding is an int.
                    None => Kind::Scalar {
                        bytes,
                        signed: true,
                    },
                    _ => Kind::Scalar {
                        bytes,
                        signed: false,
                    },
                };
            }
            _ => return Kind::Other,
        }
    }
}
