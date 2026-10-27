use serde::Serialize;

use crate::analysis::{Analysis, refs};
use crate::error::LiftError;
use crate::ir::{CType, Stmt, Structure};
use crate::loader::{Function, Image, NameSource};
use crate::{addr, disasm};

const PREVIEW_MAX_BYTES: u64 = 256;
const BASE_TOKENS: usize = 96;
const TOKENS_PER_LINE: usize = 6;
pub const DEFAULT_BUDGET: usize = 240;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HardReason {
    BoundaryUnknown,
    NameUnknown,
}

/// A memory access type in a recovered structure, without a source field name.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StructureField {
    /// Byte offset from the structure pointer, written in hexadecimal.
    pub offset: String,
    /// The C type used for this access.
    pub r#type: String,
    /// Width of the access in bytes.
    pub size: u64,
}

/// An inferred layout; its access types need not be the original source types.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StructureLayout {
    /// The generated C structure tag.
    pub name: String,
    /// Known array stride in bytes, or null when no stride was established.
    pub element_size: Option<u64>,
    /// End of the last observed field, excluding unobserved trailing bytes.
    pub minimum_size: u64,
    /// Observed access views; overlapping entries do not prove a source union.
    pub fields: Vec<StructureField>,
    /// Original declared members, unknown from memory accesses alone.
    pub source_fields: Option<Vec<StructureField>>,
    /// Original declared size, unknown from a stride or minimum access extent alone.
    pub source_size: Option<u64>,
}

impl From<&Structure> for StructureLayout {
    fn from(layout: &Structure) -> Self {
        let mut minimum_size = 0;
        let mut fields = Vec::new();
        for (offset, ty) in &layout.fields {
            let size = CType::pointer_to(ty.clone())
                .pointee_size()
                .map_or(0, u64::from);
            minimum_size = minimum_size.max(offset.saturating_add(size));
            fields.push(StructureField {
                offset: addr::format(*offset),
                r#type: ty.to_string(),
                size,
            });
        }
        Self {
            name: layout.name.clone(),
            element_size: layout.size,
            minimum_size,
            fields,
            source_fields: None,
            source_size: None,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    pub addr: String,
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub name_sources: Vec<NameSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<crate::sigs::Evidence>,
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub size_estimated: bool,
    pub section: Option<String>,
    pub hard_reasons: Vec<HardReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lift_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocks: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsupported: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub strings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub name_hints: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub accesses: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub structures: Vec<String>,
    /// Recovered field offsets, access types and known array strides.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub structure_layouts: Vec<StructureLayout>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identified: Option<String>,
    /// Predicate and dispatcher removals proved during analysis.
    pub simplification: crate::passes::deobfuscation::Simplification,
    pub disasm_preview: Vec<String>,
    pub approx_tokens: usize,
}

/// A card sized to roughly `budget` tokens; a larger budget adds disassembly lines.
pub fn build(
    image: &Image,
    function: &Function,
    analysis: Result<&Analysis, &LiftError>,
    identified: Option<String>,
    budget: usize,
) -> Card {
    let lines = budget.saturating_sub(BASE_TOKENS) / TOKENS_PER_LINE;
    let preview_len = function
        .size
        .map_or(PREVIEW_MAX_BYTES, |size| size.min(PREVIEW_MAX_BYTES));
    let disasm_preview = disasm::preview(image, function.addr, preview_len, lines);

    let mut hard_reasons = Vec::new();
    if function.size.is_none() {
        hard_reasons.push(HardReason::BoundaryUnknown);
    }
    if function.name.is_none() && function.sources.contains(&NameSource::Entry) {
        hard_reasons.push(HardReason::NameUnknown);
    }

    let (analysis, lift_error) = match analysis {
        Ok(analysis) => (Some(analysis), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let strings = analysis.map(|a| a.strings()).unwrap_or_default();
    Card {
        addr: addr::format(function.addr),
        name: function.name.clone(),
        aliases: function.aliases.clone(),
        name_sources: function.sources.clone(),
        library: function.library.as_deref().cloned(),
        size: function.size,
        size_estimated: function.size_estimated,
        section: image.section_at(function.addr).map(|s| s.name.clone()),
        hard_reasons,
        lift_error,
        blocks: analysis.map(|a| a.ir.blocks.len()),
        unsupported: analysis.map(|a| {
            a.ir.blocks
                .iter()
                .flat_map(|block| &block.stmts)
                .filter(|stmt| matches!(stmt, Stmt::Unsupported { .. }))
                .count()
        }),
        name_hints: refs::name_hints(&strings),
        strings,
        accesses: analysis.map(|a| a.ir.access_lines()).unwrap_or_default(),
        structures: analysis
            .map(|a| {
                a.ir.structures
                    .iter()
                    .map(|layout| {
                        crate::render::structure_definition(layout)
                            .trim_end()
                            .to_owned()
                    })
                    .collect()
            })
            .unwrap_or_default(),
        simplification: analysis.map(|a| a.simplification).unwrap_or_default(),
        structure_layouts: analysis
            .map(|a| a.ir.structures.iter().map(StructureLayout::from).collect())
            .unwrap_or_default(),
        identified,
        approx_tokens: disasm_preview.len() * TOKENS_PER_LINE + BASE_TOKENS,
        disasm_preview,
    }
}
