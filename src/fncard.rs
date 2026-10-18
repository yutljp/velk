//! Function cards: deterministic, LLM-facing summaries of a single function.

use serde::Serialize;

use crate::loader::{Function, Image, Isa, NameSource};

const PREVIEW_MAX_BYTES: u64 = 256;

#[derive(Serialize)]
pub struct FunctionCard {
    pub fid: String,
    pub name: Option<String>,
    pub source: Vec<String>,
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "is_false")]
    pub size_estimated: bool,
    pub section: Option<String>,
    pub hard_reasons: Vec<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identified: Option<String>,
    pub disasm_preview: Vec<String>,
    pub approx_tokens: u64,
}

fn is_false(value: &bool) -> bool {
    !*value
}

pub fn disassemble(image: &Image, addr: u64, len: u64, max_lines: usize) -> Vec<String> {
    let Some(bytes) = image.read_vaddr(addr, len) else {
        return Vec::new();
    };

    match image.isa {
        Isa::X86_64 => disassemble_x86(bytes, addr, max_lines),
        Isa::AArch64 => disassemble_aarch64(bytes, addr, max_lines),
        Isa::Unsupported => Vec::new(),
    }
}

fn disassemble_x86(bytes: &[u8], addr: u64, max_lines: usize) -> Vec<String> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};

    let mut decoder = Decoder::with_ip(64, bytes, addr, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut lines = Vec::new();

    while lines.len() < max_lines && decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        lines.push(format!("0x{:<12x} {}", instruction.ip(), instruction));
        if matches!(
            instruction.flow_control(),
            FlowControl::Return
                | FlowControl::UnconditionalBranch
                | FlowControl::Exception
                | FlowControl::Interrupt
        ) {
            break;
        }
    }

    lines
}

fn disassemble_aarch64(bytes: &[u8], addr: u64, max_lines: usize) -> Vec<String> {
    use yaxpeax_arch::{Decoder, ReaderBuilder};
    use yaxpeax_arm::armv8::a64;

    let mut reader = ReaderBuilder::<u64, u8>::read_at(bytes, 0);
    let decoder = a64::InstDecoder::default();
    let mut lines = Vec::new();
    let mut pc = addr;

    for _ in 0..(bytes.len() / 4) {
        if lines.len() >= max_lines {
            break;
        }
        match decoder.decode(&mut reader) {
            Ok(instruction) => {
                lines.push(format!("0x{:<12x} {}", pc, instruction));
                let returns = instruction.opcode == a64::Opcode::RET;
                pc += 4;
                if returns {
                    break;
                }
            }
            Err(error) => {
                lines.push(format!("0x{:<12x} (undecodable: {})", pc, error));
                break;
            }
        }
    }

    lines
}

pub fn build(
    image: &Image,
    func: &Function,
    max_lines: usize,
    lifted: Option<&crate::ir::FunctionIr>,
    strings: Vec<String>,
    name_hints: Vec<String>,
    accesses: Vec<String>,
    identified: Option<String>,
) -> FunctionCard {
    let preview_len = func.size.unwrap_or(PREVIEW_MAX_BYTES).min(PREVIEW_MAX_BYTES);
    let disasm_preview = disassemble(image, func.addr, preview_len, max_lines);

    let mut hard_reasons = Vec::new();
    if func.size.is_none() {
        hard_reasons.push("boundary-unknown".to_owned());
    }
    if func.name.is_none() && func.source.contains(&NameSource::Entry) {
        hard_reasons.push("name-unknown".to_owned());
    }

    let blocks = lifted.map(|ir| ir.blocks.len());
    let unsupported = lifted.map(|ir| {
        ir.blocks
            .iter()
            .flat_map(|block| block.stmts.iter())
            .filter(|stmt| matches!(stmt, crate::ir::Stmt::Unsupported { .. }))
            .count()
    });

    FunctionCard {
        fid: format!("0x{:x}", func.addr),
        name: func.name.clone(),
        source: func.source.iter().map(ToString::to_string).collect(),
        size: func.size,
        size_estimated: func.size_estimated,
        section: image.section_at(func.addr).map(|s| s.name.clone()),
        hard_reasons,
        blocks,
        unsupported,
        strings,
        name_hints,
        accesses,
        identified,
        approx_tokens: disasm_preview.len() as u64 * 6 + 96,
        disasm_preview,
    }
}
