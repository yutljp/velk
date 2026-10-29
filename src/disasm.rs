use std::collections::{HashMap, HashSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};
use serde::Serialize;
use yaxpeax_arch::{Decoder as _, ReaderBuilder};
use yaxpeax_arm::armv8::a64;

use crate::error::LiftError;
use crate::loader::{Image, Isa};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Extent {
    FirstExit,
    Whole,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ReferenceKind {
    Branch,
    Memory,
    LiteralPool,
    IndirectControlFlow,
    Address,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Reference {
    pub(crate) address: u64,
    pub(crate) kind: ReferenceKind,
}

#[derive(Debug)]
pub(crate) struct RawInstruction {
    pub(crate) addr: u64,
    pub(crate) end: u64,
    pub(crate) text: String,
    pub(crate) reference: Option<Reference>,
}

/// One decoded instruction and the name or string found at its referenced address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DisassemblyLine {
    #[serde(serialize_with = "crate::addr::serialize")]
    pub addr: u64,
    pub instruction: String,
    pub comment: Option<String>,
}

/// Disassembles a function and attaches comments for statically known references.
pub fn listing(
    image: &Image,
    addr: u64,
    len: u64,
    max_lines: usize,
    decoded_strings: &[crate::string_decoding::DecodedString],
) -> Result<Vec<DisassemblyLine>, LiftError> {
    let addr = image.code_address(addr);
    let Some(bytes) = image.read_vaddr(addr, len) else {
        return Err(LiftError::Unreadable);
    };
    let decoded = decode(image, bytes, addr, max_lines, Extent::Whole)?;
    let literals = literal_strings(image, &decoded);
    Ok(decoded
        .into_iter()
        .map(|instruction| {
            let comment = comment(image, &instruction, &literals, decoded_strings);
            DisassemblyLine {
                addr: instruction.addr,
                instruction: instruction.text,
                comment,
            }
        })
        .collect())
}

fn literal_strings(image: &Image, instructions: &[RawInstruction]) -> HashMap<u64, String> {
    let mut addresses = HashSet::new();
    for instruction in instructions {
        let Some(reference) = instruction.reference else {
            continue;
        };
        let string_candidate = match reference.kind {
            ReferenceKind::Branch => image.format == crate::loader::Format::Raw,
            ReferenceKind::Memory | ReferenceKind::LiteralPool | ReferenceKind::Address => true,
            ReferenceKind::IndirectControlFlow => false,
        };
        if string_candidate {
            addresses.insert(reference.address);
        }
        if matches!(reference.kind, ReferenceKind::LiteralPool)
            && let Some(crate::loader::Pointer::Address(address)) =
                image.read_pointer(reference.address)
        {
            addresses.insert(address);
        }
    }
    let mut literals = HashMap::new();
    for address in addresses {
        if let Some(text) = crate::xrefs::string_at(image, address) {
            literals.insert(address, text);
        }
    }
    literals
}

/// Renders instruction records as lines, aligning comments to the same column.
pub fn format_lines(lines: &[DisassemblyLine]) -> Vec<String> {
    let prefixes: Vec<String> = lines
        .iter()
        .map(|line| format!("0x{:<12x} {}", line.addr, line.instruction))
        .collect();
    let column = prefixes.iter().map(String::len).max().unwrap_or(0);
    lines
        .iter()
        .zip(prefixes)
        .map(|(line, prefix)| match &line.comment {
            Some(comment) => format!("{prefix:<column$} ; {comment}"),
            None => prefix,
        })
        .collect()
}

/// The opening instructions up to the first exit; empty when the bytes cannot be read.
pub fn preview(image: &Image, addr: u64, len: u64, max_lines: usize) -> Vec<String> {
    let addr = image.code_address(addr);
    let Some(bytes) = image.read_vaddr(addr, len) else {
        return Vec::new();
    };
    match decode(image, bytes, addr, max_lines, Extent::FirstExit) {
        Ok(decoded) => raw_lines(&decoded),
        Err(_) => Vec::new(),
    }
}

fn decode(
    image: &Image,
    bytes: &[u8],
    addr: u64,
    max_lines: usize,
    extent: Extent,
) -> Result<Vec<RawInstruction>, LiftError> {
    match image.isa {
        Isa::I386 => Ok(x86(bytes, addr, max_lines, extent, 32)),
        Isa::X86_64 => Ok(x86(bytes, addr, max_lines, extent, 64)),
        Isa::AArch64 => Ok(aarch64(bytes, addr, max_lines, extent)),
        Isa::Arm32
            if matches!(
                image.format,
                crate::loader::Format::Elf | crate::loader::Format::Raw
            ) && image.byte_order() == Some(object::Endianness::Little) =>
        {
            Ok(crate::lift::arm32_disassembly(
                image, bytes, addr, max_lines,
            ))
        }
        Isa::Arm32 | Isa::Unsupported => Err(LiftError::UnsupportedIsa),
    }
}

fn raw_lines(lines: &[RawInstruction]) -> Vec<String> {
    lines
        .iter()
        .map(|line| format!("0x{:<12x} {}", line.addr, line.text))
        .collect()
}

fn x86(
    bytes: &[u8],
    addr: u64,
    max_lines: usize,
    extent: Extent,
    bitness: u32,
) -> Vec<RawInstruction> {
    let mut decoder = Decoder::with_ip(bitness, bytes, addr, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut lines = Vec::new();
    while lines.len() < max_lines && decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        let Ok(length) = u64::try_from(instruction.len()) else {
            break;
        };
        let Some(end) = instruction.ip().checked_add(length) else {
            break;
        };
        let reference = x86_reference(&instruction, bitness);
        lines.push(RawInstruction {
            addr: instruction.ip(),
            end,
            text: instruction.to_string(),
            reference,
        });
        let exits = matches!(
            instruction.flow_control(),
            FlowControl::Return
                | FlowControl::UnconditionalBranch
                | FlowControl::Exception
                | FlowControl::Interrupt
        );
        if extent == Extent::FirstExit && exits {
            break;
        }
    }
    lines
}

fn x86_reference(instruction: &Instruction, bitness: u32) -> Option<Reference> {
    let branch = (0..instruction.op_count()).any(|operand| {
        matches!(
            instruction.op_kind(operand),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        )
    });
    if branch {
        return Some(Reference {
            address: instruction.near_branch_target(),
            kind: ReferenceKind::Branch,
        });
    }
    if (0..instruction.op_count()).any(|operand| instruction.op_kind(operand) == OpKind::Memory) {
        if matches!(instruction.memory_segment(), Register::FS | Register::GS) {
            return x86_immediate_reference(instruction, bitness);
        }
        let address = if instruction.is_ip_rel_memory_operand() {
            instruction.ip_rel_memory_address()
        } else if instruction.memory_base() == Register::None
            && instruction.memory_index() == Register::None
        {
            instruction.memory_displacement64()
        } else {
            return x86_immediate_reference(instruction, bitness);
        };
        let indirect_control = matches!(
            instruction.flow_control(),
            FlowControl::IndirectCall | FlowControl::IndirectBranch
        );
        return Some(Reference {
            address,
            kind: if indirect_control {
                ReferenceKind::IndirectControlFlow
            } else {
                ReferenceKind::Memory
            },
        });
    }
    x86_immediate_reference(instruction, bitness)
}

fn x86_immediate_reference(instruction: &Instruction, bitness: u32) -> Option<Reference> {
    if bitness != 32 {
        return None;
    }
    for operand in 0..instruction.op_count() {
        let kind = instruction.op_kind(operand);
        if matches!(
            kind,
            OpKind::Immediate8
                | OpKind::Immediate8to16
                | OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate64
                | OpKind::Immediate32to64
        ) {
            return Some(Reference {
                address: instruction.immediate(operand),
                kind: ReferenceKind::Address,
            });
        }
    }
    None
}

fn aarch64(bytes: &[u8], addr: u64, max_lines: usize, extent: Extent) -> Vec<RawInstruction> {
    let mut reader = ReaderBuilder::<u64, u8>::read_at(bytes, 0);
    let decoder = a64::InstDecoder::default();
    let mut lines = Vec::new();
    let mut page_register = None;
    for index in 0..(bytes.len() / 4).min(max_lines) {
        let Some(offset) = (index as u64).checked_mul(4) else {
            break;
        };
        let Some(pc) = addr.checked_add(offset) else {
            break;
        };
        let Some(end) = pc.checked_add(4) else {
            break;
        };
        match decoder.decode(&mut reader) {
            Ok(instruction) => {
                let reference = aarch64_reference(&instruction, pc, &mut page_register);
                lines.push(RawInstruction {
                    addr: pc,
                    end,
                    text: instruction.to_string(),
                    reference,
                });
                if extent == Extent::FirstExit
                    && matches!(
                        instruction.opcode,
                        a64::Opcode::RET | a64::Opcode::RETAA | a64::Opcode::RETAB
                    )
                {
                    break;
                }
            }
            Err(error) => {
                lines.push(RawInstruction {
                    addr: pc,
                    end,
                    text: format!("(undecodable: {error})"),
                    reference: None,
                });
                break;
            }
        }
    }
    lines
}

fn aarch64_reference(
    instruction: &a64::Instruction,
    pc: u64,
    page_register: &mut Option<(u16, u64)>,
) -> Option<Reference> {
    use a64::{Opcode, Operand};

    let [first, second, third, _] = instruction.operands;
    let branch = matches!(
        instruction.opcode,
        Opcode::B
            | Opcode::BL
            | Opcode::Bcc(_)
            | Opcode::BCcc(_)
            | Opcode::CBZ
            | Opcode::CBNZ
            | Opcode::TBZ
            | Opcode::TBNZ
            | Opcode::RETAASPPC
            | Opcode::RETABSPPC
    );
    if branch {
        page_register.take();
        let Some(target) = instruction
            .operands
            .iter()
            .find_map(|operand| match operand {
                Operand::PCOffset(offset) => pc.checked_add_signed(*offset),
                _ => None,
            })
        else {
            return None;
        };
        return Some(Reference {
            address: target,
            kind: ReferenceKind::Branch,
        });
    }

    if instruction.opcode == Opcode::ADR {
        page_register.take();
        if let Operand::PCOffset(offset) = second {
            return pc.checked_add_signed(offset).map(|address| Reference {
                address,
                kind: ReferenceKind::Address,
            });
        }
        return None;
    }
    if instruction.opcode == Opcode::ADRP {
        let address = match second {
            Operand::PCOffset(offset) => (pc & !0xfff).checked_add_signed(offset),
            _ => None,
        };
        let register = aarch64_register(first);
        *page_register = register.zip(address);
        return None;
    }
    if matches!(
        instruction.opcode,
        Opcode::LDR | Opcode::LDRSW | Opcode::PRFM
    ) && let Operand::PCOffset(offset) = second
    {
        page_register.take();
        return pc.checked_add_signed(offset).map(|address| Reference {
            address,
            kind: ReferenceKind::LiteralPool,
        });
    }

    if let Some((register, page)) = page_register.take() {
        if matches!(instruction.opcode, Opcode::ADD | Opcode::ADDS)
            && aarch64_register(second) == Some(register)
            && let Some(offset) = aarch64_immediate(third)
            && let Some(address) = page.checked_add(offset)
        {
            return Some(Reference {
                address,
                kind: ReferenceKind::Address,
            });
        }
        if let Some(address) = aarch64_memory_address(instruction, register, page) {
            return Some(Reference {
                address,
                kind: ReferenceKind::Memory,
            });
        }
    }
    None
}

fn aarch64_register(operand: a64::Operand) -> Option<u16> {
    match operand {
        a64::Operand::Register(_, register) | a64::Operand::RegisterOrSP(_, register)
            if register < 31 =>
        {
            Some(register)
        }
        _ => None,
    }
}

fn aarch64_immediate(operand: a64::Operand) -> Option<u64> {
    match operand {
        a64::Operand::ImmShift(value, shift) => Some(u64::from(value) << shift),
        a64::Operand::Immediate(value) => Some(u64::from(value)),
        a64::Operand::Imm16(value) => Some(u64::from(value)),
        _ => None,
    }
}

fn aarch64_memory_address(instruction: &a64::Instruction, register: u16, page: u64) -> Option<u64> {
    for operand in instruction.operands {
        match operand {
            a64::Operand::RegPreIndex(base, offset, _) if base == register => {
                return page.checked_add_signed(i64::from(offset));
            }
            a64::Operand::RegPostIndex(base, _) if base == register => return Some(page),
            _ => {}
        }
    }
    None
}

fn comment(
    image: &Image,
    instruction: &RawInstruction,
    literals: &HashMap<u64, String>,
    decoded_strings: &[crate::string_decoding::DecodedString],
) -> Option<String> {
    let relocation = image
        .relocation_symbols
        .range(instruction.addr..instruction.end)
        .next()
        .map(|(_, name)| name);
    if image.relocatable {
        if relocation.is_none() {
            return None;
        }
        return relocation.cloned();
    }
    if let Some(reference) = instruction.reference {
        if let Some(text) = literals.get(&reference.address) {
            return Some(quoted(text));
        }
        match reference.kind {
            ReferenceKind::Branch => {
                if let Some(name) = image.imports.get(&reference.address) {
                    return Some(name.clone());
                }
                if let Some(name) = function_name(image, reference.address) {
                    return Some(name);
                }
            }
            ReferenceKind::IndirectControlFlow => {
                if let Some(name) = image.imports.get(&reference.address) {
                    return Some(name.clone());
                }
            }
            ReferenceKind::Memory => {
                if let Some(name) = image.imports.get(&reference.address) {
                    return Some(name.clone());
                }
                if let Some(name) = image.data_symbols.get(&reference.address) {
                    return Some(name.clone());
                }
            }
            ReferenceKind::LiteralPool => {
                if let Some(pointer) = image.read_pointer(reference.address) {
                    match pointer {
                        crate::loader::Pointer::Import { name, .. } => {
                            return Some(name.to_owned());
                        }
                        crate::loader::Pointer::Address(address) => {
                            if let Some(text) = literals.get(&address) {
                                return Some(quoted(text));
                            }
                            if let Some(name) = image.data_symbols.get(&address) {
                                return Some(name.clone());
                            }
                            if let Some(name) = function_name(image, address) {
                                return Some(name);
                            }
                        }
                    }
                }
                if let Some(name) = image.data_symbols.get(&reference.address) {
                    return Some(name.clone());
                }
            }
            ReferenceKind::Address => {
                if let Some(name) = image.data_symbols.get(&reference.address) {
                    return Some(name.clone());
                }
                if let Some(name) = function_name(image, reference.address) {
                    return Some(name);
                }
            }
        }
        if let Some(string) = decoded_strings
            .iter()
            .find(|string| string.addr == reference.address)
        {
            return Some(quoted(&string.text));
        }
    }
    None
}

fn function_name(image: &Image, address: u64) -> Option<String> {
    let address = image.code_address(address);
    let Some((start, function)) = image.functions.range(..=address).next_back() else {
        return None;
    };
    let Some(name) = function.name.as_deref() else {
        return None;
    };
    if *start == address {
        return Some(name.to_owned());
    }
    let Some(size) = function.size else {
        return None;
    };
    let Some(end) = start.checked_add(size) else {
        return None;
    };
    (address < end).then(|| format!("{name}+0x{:x}", address - start))
}

fn quoted(text: &str) -> String {
    const WIDTH: usize = 48;
    let mut quoted = String::from("\"");
    let mut characters = text.chars();
    for character in characters.by_ref().take(WIDTH) {
        match character {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            character if character.is_control() => {
                quoted.push_str(&format!("\\u{{{:x}}}", u32::from(character)));
            }
            character => quoted.push(character),
        }
    }
    if characters.next().is_some() {
        quoted.push('…');
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::loader::{Image, Isa};

    use super::{
        DisassemblyLine, RawInstruction, Reference, ReferenceKind, comment, format_lines, listing,
        quoted,
    };

    #[test]
    fn resolves_x86_pc_relative_and_i386_absolute_memory() {
        let mut x86 = Image::from_code(
            Isa::X86_64,
            0x1000,
            vec![0x48, 0x8d, 0x3d, 0xf9, 0x0f, 0x00, 0x00],
        );
        x86.data_symbols.insert(0x2000, "g_name".to_owned());
        let lines = listing(&x86, 0x1000, 7, 1, &[]).expect("x86 listing");
        assert_eq!(lines[0].comment.as_deref(), Some("g_name"));

        let mut i386 = Image::from_code(Isa::I386, 0x1000, vec![0xa1, 0x00, 0x20, 0x00, 0x00]);
        i386.data_symbols.insert(0x2000, "g_counter".to_owned());
        let lines = listing(&i386, 0x1000, 5, 1, &[]).expect("i386 listing");
        assert_eq!(lines[0].comment.as_deref(), Some("g_counter"));
    }

    #[test]
    fn resolves_aarch64_adrp_add_pair() {
        let code: Vec<u8> = [0x90000000u32, 0x9100c000, 0xd65f03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let mut image = Image::from_code(Isa::AArch64, 0x1000, code);
        image.data_symbols.insert(0x1030, "g_counter".to_owned());
        let lines = listing(&image, 0x1000, 12, 3, &[]).expect("AArch64 listing");
        assert_eq!(lines[1].comment.as_deref(), Some("g_counter"));
    }

    #[test]
    fn relocatable_operands_need_a_named_relocation() {
        let mut image = Image::from_code(Isa::X86_64, 0x1000, vec![0xe8, 0, 0, 0, 0]);
        image.relocatable = true;
        let lines = listing(&image, 0x1000, 5, 1, &[]).expect("relocatable listing");
        assert_eq!(lines[0].comment, None);

        image
            .relocation_symbols
            .insert(0x1001, "external_call".to_owned());
        let lines = listing(&image, 0x1000, 5, 1, &[]).expect("relocated listing");
        assert_eq!(lines[0].comment.as_deref(), Some("external_call"));

        let instruction = RawInstruction {
            addr: 0x1000,
            end: 0x1005,
            text: "call 0x1005".to_owned(),
            reference: Some(Reference {
                address: 0x1005,
                kind: ReferenceKind::Branch,
            }),
        };
        let literals = HashMap::from([(0x1005, "placeholder".to_owned())]);
        assert_eq!(
            comment(&image, &instruction, &literals, &[]).as_deref(),
            Some("external_call")
        );
    }

    #[test]
    fn resolves_memory_references_to_imports() {
        let mut image = Image::from_code(Isa::X86_64, 0x1000, vec![0x90]);
        image.imports.insert(0x2000, "imported_data".to_owned());
        let instruction = RawInstruction {
            addr: 0x1000,
            end: 0x1001,
            text: "mov rax, [0x2000]".to_owned(),
            reference: Some(Reference {
                address: 0x2000,
                kind: ReferenceKind::Memory,
            }),
        };
        assert_eq!(
            comment(&image, &instruction, &HashMap::new(), &[]).as_deref(),
            Some("imported_data")
        );
    }

    #[test]
    fn string_comments_precede_symbols_and_are_escaped_and_truncated() {
        let image = Image::from_code(
            Isa::X86_64,
            0x1000,
            vec![0x48, 0x8d, 0x3d, 0xf9, 0x0f, 0x00, 0x00],
        );
        let instruction = RawInstruction {
            addr: 0x1000,
            end: 0x1007,
            text: "lea rdi, [rip + 0xff9]".to_owned(),
            reference: Some(Reference {
                address: 0x2000,
                kind: ReferenceKind::Memory,
            }),
        };
        let mut image = image;
        image.data_symbols.insert(0x2000, "g_name".to_owned());
        let literals = HashMap::from([(0x2000, "a\"bc".to_owned())]);
        assert_eq!(
            comment(&image, &instruction, &literals, &[]).as_deref(),
            Some("\"a\\\"bc\"")
        );
        assert_eq!(quoted(&"x".repeat(50)), format!("\"{}…\"", "x".repeat(48)));
        let wide = HashMap::from([(0x2000, "wide😀".to_owned())]);
        assert_eq!(
            comment(&image, &instruction, &wide, &[]).as_deref(),
            Some("\"wide😀\"")
        );
    }

    #[test]
    fn uses_a_previously_decoded_string_at_the_referenced_address() {
        let image = Image::from_code(
            Isa::X86_64,
            0x1000,
            vec![0x48, 0x8d, 0x3d, 0xf9, 0x0f, 0x00, 0x00],
        );
        let decoded = crate::string_decoding::DecodedString {
            addr: 0x2000,
            function: 0x1000,
            site: 0x1000,
            decoder: 0x1000,
            decoder_name: None,
            stack: false,
            encoding: "utf8",
            text: "decoded-name".to_owned(),
            target: None,
        };
        let lines =
            listing(&image, 0x1000, 7, 1, &[decoded]).expect("listing with a decoded string");
        assert_eq!(lines[0].comment.as_deref(), Some("\"decoded-name\""));
    }

    #[test]
    fn comments_align_in_text_output() {
        let lines = [
            DisassemblyLine {
                addr: 0x10,
                instruction: "ret".to_owned(),
                comment: Some("return".to_owned()),
            },
            DisassemblyLine {
                addr: 0x20,
                instruction: "call 0x30".to_owned(),
                comment: Some("target".to_owned()),
            },
        ];
        let rendered = format_lines(&lines);
        let first_semicolon = rendered[0].find(';').expect("first comment");
        let second_semicolon = rendered[1].find(';').expect("second comment");
        assert_eq!(first_semicolon, second_semicolon);
        assert!(rendered[1].ends_with("; target"));
    }
}
