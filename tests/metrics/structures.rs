//! Compare pointer layouts with DWARF independently of stripped analysis.

use super::{AttributeValue, CType, Kind, Slice, common, kind_of, truth, type_kind};
use std::fmt::Write as _;
use velk::ir::Structure;
use velk::service::Binary;

pub(super) struct TruthLayout {
    size: u64,
    fields: Vec<TruthField>,
}

struct TruthField {
    offset: u64,
    kind: Kind,
    size: Option<u64>,
}

fn type_size(
    unit: &gimli::Unit<Slice<'_>>,
    value: Option<AttributeValue<Slice<'_>>>,
) -> Option<u64> {
    let Some(AttributeValue::UnitRef(mut offset)) = value else {
        return None;
    };
    for _ in 0..64 {
        let entry = unit.entry(offset).expect("DWARF field type");
        if let Some(size) = entry
            .attr_value(gimli::DW_AT_byte_size)
            .and_then(|value| value.udata_value())
        {
            return Some(size);
        }
        match entry.tag() {
            gimli::DW_TAG_pointer_type | gimli::DW_TAG_reference_type => {
                return Some(u64::from(unit.encoding().address_size));
            }
            gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type => {}
            _ => return None,
        }
        let Some(AttributeValue::UnitRef(next)) = entry.attr_value(gimli::DW_AT_type) else {
            return None;
        };
        offset = next;
    }
    None
}

pub(super) fn pointer_layout(
    unit: &gimli::Unit<Slice<'_>>,
    value: Option<AttributeValue<Slice<'_>>>,
) -> Option<TruthLayout> {
    let Some(AttributeValue::UnitRef(mut offset)) = value else {
        return None;
    };
    let mut pointer = false;
    // Bound malformed or cyclic type references.
    for _ in 0..64 {
        let entry = unit.entry(offset).expect("DWARF type");
        match entry.tag() {
            gimli::DW_TAG_pointer_type if !pointer => pointer = true,
            gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type => {}
            gimli::DW_TAG_structure_type if pointer => {
                let size = entry
                    .attr_value(gimli::DW_AT_byte_size)
                    .and_then(|value| value.udata_value())
                    .expect("structure size");
                let mut tree = unit.entries_tree(Some(offset)).expect("structure tree");
                let root = tree.root().expect("structure root");
                let mut children = root.children();
                let mut fields = Vec::new();
                while let Some(child) = children.next().expect("structure member") {
                    let entry = child.entry();
                    if entry.tag() != gimli::DW_TAG_member {
                        continue;
                    }
                    // Bit fields and expression locations need separate layout rules.
                    if entry.attr_value(gimli::DW_AT_bit_size).is_some() {
                        continue;
                    }
                    let Some(offset) = entry
                        .attr_value(gimli::DW_AT_data_member_location)
                        .and_then(|value| value.udata_value())
                    else {
                        continue;
                    };
                    fields.push(TruthField {
                        offset,
                        kind: type_kind(unit, entry.attr_value(gimli::DW_AT_type)),
                        size: type_size(unit, entry.attr_value(gimli::DW_AT_type)),
                    });
                }
                return Some(TruthLayout { size, fields });
            }
            _ => return None,
        }
        let Some(AttributeValue::UnitRef(next)) = entry.attr_value(gimli::DW_AT_type) else {
            return None;
        };
        offset = next;
    }
    None
}

#[derive(Default)]
struct Counts {
    correct: usize,
    wrong: usize,
    missed: usize,
}

impl Counts {
    fn add(&mut self, correct: Option<bool>) {
        match correct {
            Some(true) => self.correct += 1,
            Some(false) => self.wrong += 1,
            None => self.missed += 1,
        }
    }
}

fn compare(expected: &TruthLayout, got: Option<&Structure>, scores: &mut [Counts; 4]) {
    scores[3].add(
        got.and_then(|layout| layout.size)
            .map(|size| size == expected.size),
    );
    for field in &expected.fields {
        let found = got.and_then(|layout| layout.fields.iter().find(|(at, _)| *at == field.offset));
        scores[0].add(found.map(|_| true));
        let width = found.and_then(|(_, ty)| CType::pointer_to(ty.clone()).pointee_size());
        scores[1].add(
            field
                .size
                .zip(width)
                .map(|(want, got)| want == u64::from(got)),
        );
        scores[2].add(found.map(|(_, ty)| field.kind == kind_of(ty)));
    }
    if let Some(got) = got {
        for (offset, _) in &got.fields {
            if !expected.fields.iter().any(|field| field.offset == *offset) {
                for score in &mut scores[..3] {
                    score.wrong += 1;
                }
            }
        }
    }
}

fn differences(expected: &TruthLayout, got: &Structure) -> Vec<String> {
    let mut differences = Vec::new();
    if let Some(size) = got.size
        && size != expected.size
    {
        differences.push(format!("stride {size}, declared size {}", expected.size));
    }
    for (offset, ty) in &got.fields {
        let Some(field) = expected.fields.iter().find(|field| field.offset == *offset) else {
            differences.push(format!("access at {offset:#x} has no direct source member"));
            continue;
        };
        let width = CType::pointer_to(ty.clone()).pointee_size().map(u64::from);
        if width != field.size || kind_of(ty) != field.kind {
            differences.push(format!(
                "access at {offset:#x}: {ty} ({width:?} bytes), source {:?} ({:?} bytes)",
                field.kind, field.size,
            ));
        }
    }
    differences
}

#[test]
fn stripped_structure_layouts_match_debug_information() {
    let dir = common::fixtures_dir().join("metrics");
    let mut cases = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("metrics fixtures") {
        let entry = entry.expect("fixture entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("structs.") || name.starts_with("struct_arrays.") {
            for extension in ["elf", "dll"] {
                if let Some(case) = name.strip_suffix(&format!(".debug.{extension}")) {
                    cases.push((case.to_owned(), extension));
                }
            }
        }
    }
    cases.sort();
    assert!(!cases.is_empty());
    let mut output = String::from(
        "# fixture | metric | correct | wrong | missed\n# Access views compared with direct non-bit-field source members; aggregates are not flattened.\n# Access types and strides need not be declared source types and sizes.\n# Source metrics count only sourceFields/sourceSize; unknown facts count as missed.\n",
    );
    for (case, extension) in cases {
        let expected = truth(&dir.join(format!("{case}.debug.{extension}")));
        let mut binary = Binary::open(&dir.join(format!("{case}.stripped.{extension}")))
            .expect("stripped fixture");
        let mut scores: [Counts; 4] = Default::default();
        let mut source_scores: [Counts; 4] = Default::default();
        for (addr, function) in expected {
            let analysis = binary.analysis(addr, None).ok();
            let params: Vec<_> = analysis
                .map(|analysis| {
                    analysis
                        .ir
                        .params
                        .iter()
                        .filter(|param| param.name != "result")
                        .collect()
                })
                .unwrap_or_default();
            for (position, expected) in function.layouts.iter().enumerate() {
                let Some(expected) = expected else { continue };
                let param = if params.len() == function.params.len() {
                    params.get(position).copied()
                } else {
                    None
                };
                let layout = match (analysis, param) {
                    (Some(analysis), Some(param)) => analysis.ir.structures.iter().find(|layout| {
                        param.ty
                            == CType::pointer_to(CType::Named(format!("struct {}", layout.name)))
                    }),
                    _ => None,
                };
                compare(expected, layout, &mut scores);
                if let Some(layout) = layout {
                    let data = velk::card::StructureLayout::from(layout);
                    assert!(data.source_fields.is_none() && data.source_size.is_none());
                    for difference in differences(expected, layout) {
                        writeln!(
                            output,
                            "# {case} {} parameter {position}: {difference}",
                            function.name
                        )
                        .expect("write difference");
                    }
                }
                compare(expected, None, &mut source_scores);
            }
        }
        for (metric, score) in [
            "field offsets",
            "field widths",
            "field types",
            "element sizes",
        ]
        .iter()
        .zip(scores)
        {
            writeln!(
                output,
                "{case} | {metric} | {} | {} | {}",
                score.correct, score.wrong, score.missed
            )
            .expect("write score");
        }
        for (metric, score) in [
            "source field offsets",
            "source field widths",
            "source field types",
            "source sizes",
        ]
        .iter()
        .zip(source_scores)
        {
            writeln!(
                output,
                "{case} | {metric} | {} | {} | {}",
                score.correct, score.wrong, score.missed
            )
            .expect("write source score");
        }
    }
    if let Some(diff) = common::check_expected(
        &common::root().join("tests/golden/structure_accuracy.txt"),
        &output,
    ) {
        panic!("structure accuracy changed: {diff}");
    }
}

#[test]
fn layout_scores_distinguish_missing_extra_and_wrong_fields() {
    let expected = TruthLayout {
        size: 16,
        fields: vec![
            TruthField {
                offset: 0,
                size: Some(4),
                kind: Kind::Scalar {
                    bytes: 4,
                    signed: true,
                },
            },
            TruthField {
                offset: 8,
                size: Some(8),
                kind: Kind::Scalar {
                    bytes: 8,
                    signed: true,
                },
            },
        ],
    };
    let got = Structure {
        name: "sample".into(),
        size: Some(24),
        elements: Vec::new(),
        fields: vec![(0, CType::U32), (4, CType::I32)],
    };
    let mut scores = Default::default();
    compare(&expected, Some(&got), &mut scores);
    assert_eq!(
        (scores[0].correct, scores[0].wrong, scores[0].missed),
        (1, 1, 1)
    );
    assert_eq!(
        (scores[1].correct, scores[1].wrong, scores[1].missed),
        (1, 1, 1)
    );
    assert_eq!(
        (scores[2].correct, scores[2].wrong, scores[2].missed),
        (0, 2, 1)
    );
    assert_eq!(
        (scores[3].correct, scores[3].wrong, scores[3].missed),
        (0, 1, 0)
    );
}
