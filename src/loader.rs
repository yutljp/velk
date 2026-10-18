//! Loader: ELF / PE を統一モデル(Image)に変換する。

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use object::read::{File as ObjFile, Object, ObjectSection, ObjectSymbol};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Elf,
    Pe,
    Coff,
    MachO,
    Other,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Format::Elf => "elf",
            Format::Pe => "pe",
            Format::Coff => "coff",
            Format::MachO => "macho",
            Format::Other => "other",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isa {
    X86_64,
    AArch64,
    Unsupported,
}

impl fmt::Display for Isa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Isa::X86_64 => "x86-64",
            Isa::AArch64 => "aarch64",
            Isa::Unsupported => "unsupported",
        })
    }
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub vaddr: u64,
    pub size: u64,
    pub file_offset: Option<u64>,
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameSource {
    SymbolTable,
    Dynamic,
    Entry,
    GoPclntab,
    Dwarf,
    /// Found by the prologue a compiler emits, in a stripped image.
    Prologue,
}

impl fmt::Display for NameSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NameSource::SymbolTable => "symtab",
            NameSource::Dynamic => "dyn",
            NameSource::Entry => "entry",
            NameSource::GoPclntab => "go",
            NameSource::Dwarf => "dwarf",
            NameSource::Prologue => "prologue",
        })
    }
}

#[derive(Debug, Clone)]
pub struct Function {
    pub addr: u64,
    pub size: Option<u64>,
    pub size_estimated: bool,
    pub name: Option<String>,
    pub source: Vec<NameSource>,
}

impl Function {
    fn merge(&mut self, name: Option<String>, size: Option<u64>, source: NameSource) {
        if let Some(name) = name {
            let name = demangle(&name).unwrap_or(name);
            self.name = match self.name.take() {
                None => Some(name),
                Some(current) if current == name => Some(current),
                Some(current) if current.starts_with('/') => Some(name),
                Some(current) if name.starts_with('/') => Some(current),
                Some(current) => Some(format!("{current}|{name}")),
            };
        }
        if self.size.is_none() {
            self.size = size;
        }
        if !self.source.contains(&source) {
            self.source.push(source);
        }
    }
}

#[derive(Debug)]
pub struct Image {
    pub format: Format,
    pub isa: Isa,
    pub entry: Option<u64>,
    bytes: Vec<u8>,
    pub sections: Vec<Section>,
    pub functions: BTreeMap<u64, Function>,
    /// Branch relocations the object left unapplied: instruction address to
    /// the symbol address it calls.
    pub relocations: BTreeMap<u64, u64>,
    /// The image carries a Go pclntab, so its functions follow the Go ABI.
    pub go: bool,
}

impl Image {
    pub fn section_at(&self, vaddr: u64) -> Option<&Section> {
        self.sections
            .iter()
            .filter(|s| vaddr >= s.vaddr && vaddr < s.vaddr.saturating_add(s.size))
            .min_by_key(|s| (!s.executable, s.size))
    }

    pub fn virtual_offset(&self, vaddr: u64) -> Option<u64> {
        let section = self.section_at(vaddr)?;
        let offset = section.file_offset?.checked_add(vaddr - section.vaddr)?;
        (offset < self.bytes.len() as u64).then_some(offset)
    }

    /// The addresses of branch instructions the linker has not bound yet.
    fn relocated_branches(&self) -> std::collections::HashSet<u64> {
        self.relocations.keys().copied().collect()
    }

    /// Adds the functions a stripped image still shows: the prologue a
    /// compiler emits at the start of the code, right after the padding
    /// that closes the function before it.
    fn scan_prologues(&mut self) {
        let mut found: Vec<u64> = Vec::new();
        for section in &self.sections {
            if !section.executable {
                continue;
            }
            let Some(bytes) = self.read_vaddr(section.vaddr, section.size) else {
                continue;
            };
            let mut starts = match self.isa {
                crate::loader::Isa::AArch64 => {
                    aarch64_prologues(bytes, section.vaddr, &self.relocated_branches())
                }
                crate::loader::Isa::X86_64 => x86_prologues(bytes, section.vaddr),
                crate::loader::Isa::Unsupported => continue,
            };
            // Code begins with a function unless padding opens the section.
            let opens = match self.isa {
                crate::loader::Isa::AArch64 => read_word(bytes, 0)
                    .is_some_and(|word| !is_aarch64_padding(word)),
                _ => bytes.first().is_some_and(|byte| !matches!(byte, 0x90 | 0xcc | 0x00)),
            };
            if opens {
                starts.insert(0, section.vaddr);
            }
            found.extend(starts);
        }
        for address in found {
            // Inside a function whose extent the symbols state is not a new
            // one; an estimated extent may well be too long to trust.
            if self.functions.range(..=address).next_back().is_some_and(
                |(start, function)| {
                    let size = function.size.unwrap_or(0);
                    *start != address
                        && !function.size_estimated
                        && size != 0
                        && address < start.saturating_add(size)
                },
            ) {
                continue;
            }
            upsert(
                &mut self.functions,
                address,
                None,
                None,
                NameSource::Prologue,
            );
        }
    }

    /// Drops the names a compiler emitted for data, which cannot be lifted.
    fn retain_code_functions(&mut self) {
        self.functions.retain(|address, _| {
            self.sections.iter().any(|section| {
                section.executable
                    && *address >= section.vaddr
                    && *address < section.vaddr.saturating_add(section.size)
            })
        });
    }

    pub fn section_data(&self, name: &str) -> Option<&[u8]> {
        let section = self.sections.iter().find(|section| section.name == name)?;
        let start = section.file_offset?;
        let end = start.checked_add(section.size)?;
        self.bytes.get(start as usize..end as usize)
    }

    pub fn read(&self, offset: u64, len: u64) -> Option<&[u8]> {
        let end = offset.checked_add(len)?;
        (end <= self.bytes.len() as u64).then(|| &self.bytes[offset as usize..end as usize])
    }

    pub fn read_vaddr(&self, vaddr: u64, len: u64) -> Option<&[u8]> {
        self.virtual_offset(vaddr)
            .and_then(|offset| self.read(offset, len))
            .or_else(|| self.read(vaddr, len))
    }

    fn add_go_functions(&mut self) {
        let mut discovered = crate::go::functions(self);
        self.go = !discovered.is_empty();
        discovered.sort_by_key(|function| function.addr);
        discovered.dedup_by_key(|function| function.addr);
        let addresses: Vec<u64> = discovered.iter().map(|function| function.addr).collect();
        for (index, function) in discovered.into_iter().enumerate() {
            let size = addresses
                .get(index + 1)
                .map(|next| next.saturating_sub(function.addr))
                .filter(|size| *size > 0 && *size <= 0x4000);
            upsert(
                &mut self.functions,
                function.addr,
                Some(function.name),
                size,
                NameSource::GoPclntab,
            );
        }
    }

    fn add_dwarf_functions(&mut self) {
        let discovered = crate::dwarf::functions(self);
        for function in discovered {
            if let Some(existing) = self.functions.get_mut(&function.addr) {
                if existing.size_estimated {
                    existing.size = None;
                    existing.size_estimated = false;
                }
            }
            upsert(
                &mut self.functions,
                function.addr,
                Some(function.name),
                Some(function.size),
                NameSource::Dwarf,
            );
        }
    }

    pub fn find_function_by_name(&self, needle: &str) -> Option<&Function> {
        self.functions
            .values()
            .find(|f| f.name.as_deref().is_some_and(|n| n.contains(needle)))
    }
}

fn isa_of(arch: object::Architecture) -> Isa {
    match arch {
        object::Architecture::X86_64 => Isa::X86_64,
        object::Architecture::Aarch64 => Isa::AArch64,
        _ => Isa::Unsupported,
    }
}

fn format_of(kind: object::FileKind) -> Format {
    use object::FileKind as K;
    match kind {
        K::Elf32 | K::Elf64 => Format::Elf,
        K::Pe32 | K::Pe64 => Format::Pe,
        K::Coff | K::CoffBig => Format::Coff,
        K::MachO32 | K::MachO64 | K::MachOFat32 | K::MachOFat64 => Format::MachO,
        _ => Format::Other,
    }
}

fn is_executable(kind: object::SectionKind) -> bool {
    matches!(kind, object::SectionKind::Text)
}

fn upsert(
    functions: &mut BTreeMap<u64, Function>,
    addr: u64,
    name: Option<String>,
    size: Option<u64>,
    source: NameSource,
) {
    functions
        .entry(addr)
        .or_insert_with(|| Function {
            addr,
            size: None,
            size_estimated: false,
            name: None,
            source: Vec::new(),
        })
        .merge(name, size, source);
}

fn symbol_name<'data, S: ObjectSymbol<'data>>(sym: &S) -> Option<String> {
    sym.name().ok().filter(|n| !n.is_empty()).map(str::to_owned)
}

fn demangle(name: &str) -> Option<String> {
    let name = name
        .strip_prefix('_')
        .filter(|_| name.starts_with("__Z") || name.starts_with("__R"))
        .unwrap_or(name);
    if let Ok(symbol) = rustc_demangle::try_demangle(name) {
        if name.starts_with("_R") || looks_like_rust_v0(name) {
            return Some(format!("{symbol:#}"));
        }
        if name.starts_with("_ZN") && name.rsplit_once("17h").is_some() {
            return Some(format!("{symbol:#}"));
        }
    }
    if name.starts_with("_Z") {
        if let Ok(symbol) = cpp_demangle::Symbol::new(name) {
            if let Ok(text) = symbol.demangle() {
                return Some(text);
            }
        }
    }
    None
}

fn looks_like_rust_v0(name: &str) -> bool {
    name.starts_with("_R") && name.len() > 3
}

/// Function starts in a stripped AArch64 image. A function ends with a
/// return (or a trap) and alignment padding, so the next instruction is
/// the start of one; a frame record push or a stack adjustment marks the
/// same boundary when the compiler emitted no padding.
fn aarch64_prologues(
    bytes: &[u8],
    base: u64,
    relocated: &std::collections::HashSet<u64>,
) -> Vec<u64> {
    let targets = aarch64_branch_targets(bytes, base);
    let mut starts = Vec::new();
    let mut offset = 0usize;
    let mut closed = false;
    while offset + 4 <= bytes.len() {
        let Some(word) = read_word(bytes, offset) else {
            offset += 4;
            continue;
        };
        let padding = is_aarch64_padding(word);
        if closed && !padding {
            // A return that something branches over is in the middle of a
            // function, and the code after it is the rest of that one.
            if !targets.contains(&(base + offset as u64)) {
                starts.push(base + offset as u64);
            }
            closed = false;
        }
        if padding {
            offset += 4;
            continue;
        }
        // Only the padding that follows a return marks a boundary: the
        // prologue alone also appears in the middle of a function. A tail
        // call leaves the function too, so the code after it opens the
        // next one.
        if matches!(word, 0xd65f_03c0 | 0xd65f_0bff | 0xd420_0000)
            // `br` leaves through a register: an indirect tail call.
            || word & 0xffff_fc1f == 0xd61f_0000
        {
            closed = true;
        } else if let Some(target) = aarch64_tail_jump(word, base + offset as u64) {
            let pc = base + offset as u64;
            // A branch to its own address is an unresolved reference (the
            // linker will fill in another function), and one that leaves
            // the section is a tail call: both close the function.
            if target == pc
                || !(base..base + bytes.len() as u64).contains(&target)
                || relocated.contains(&pc)
            {
                closed = true;
            }
        }
        offset += 4;
    }
    starts.dedup();
    starts
}

/// The target of an unconditional branch that carries its link in another
/// function: `b` without a link, decoded from the instruction word.
fn aarch64_tail_jump(word: u32, pc: u64) -> Option<u64> {
    // `b` (B.cond, CBZ and TBZ have their own patterns): bits 31..26 = 000101
    if word >> 26 != 0b000101 {
        return None;
    }
    let imm26 = (word & 0x03ff_ffff) as i64;
    let signed = (imm26 << 6) >> 6;
    Some(pc.wrapping_add((signed * 4) as u64))
}

/// Every address a direct branch in the section targets.
fn aarch64_branch_targets(bytes: &[u8], base: u64) -> std::collections::HashSet<u64> {
    use yaxpeax_arch::Decoder;
    use yaxpeax_arm::armv8::a64::{self, Operand, Opcode};
    let decoder = a64::InstDecoder::default();
    let mut targets = std::collections::HashSet::new();
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() {
        let mut reader = yaxpeax_arch::U8Reader::new(&bytes[offset..]);
        let Ok(instruction) = decoder.decode(&mut reader) else {
            offset += 4;
            continue;
        };
        let pc = base + offset as u64;
        let branch = match instruction.opcode {
            Opcode::B | Opcode::Bcc(_) | Opcode::CBZ | Opcode::CBNZ => {
                Some(instruction.operands[0])
            }
            Opcode::TBZ | Opcode::TBNZ => Some(instruction.operands[2]),
            _ => None,
        };
        if let Some(operand) = branch {
            if let Operand::PCOffset(delta) = operand {
                targets.insert(pc.wrapping_add(delta as u64));
            }
        }
        // Every AArch64 instruction is one word.
        offset += 4;
    }
    targets
}

fn read_word(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn is_aarch64_padding(word: u32) -> bool {
    matches!(
        word,
        0xd503_201f // nop
            | 0xd503_233f // paciasp
            | 0xd503_237f // pacibsp
            | 0xd503_245f // bti c
            | 0xd503_249f // bti j
            | 0x0000_0000
    )
}

/// Function starts in a stripped x86-64 image. A function ends with a
/// return, so the instruction after it — skipping the padding that follows
/// — opens the next one, unless something branches there.
/// True when the instruction at `target` is padding, which is where an
/// unresolved jump lands.
fn x86_is_padding(bytes: &[u8], base: u64, target: u64) -> bool {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic};
    if target < base {
        return false;
    }
    let offset = (target - base) as usize;
    let Some(rest) = bytes.get(offset..) else {
        return false;
    };
    let mut decoder = Decoder::with_ip(64, rest, target, DecoderOptions::NONE);
    if !decoder.can_decode() {
        return false;
    }
    matches!(decoder.decode().mnemonic(), Mnemonic::Nop | Mnemonic::Int3)
}

fn x86_prologues(bytes: &[u8], base: u64) -> Vec<u64> {
    use iced_x86::{Decoder, DecoderOptions, FlowControl};
    let mut decoder = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
    let mut starts = Vec::new();
    let mut targets = std::collections::HashSet::new();
    let mut closed = false;
    while decoder.can_decode() {
        let instruction = decoder.decode();
        let ip = instruction.ip();
        // Padding and the landing pads of earlier branches keep the search
        // open; the first real instruction after them opens a function.
        if closed && !targets.contains(&ip) && ip != base && !x86_is_padding(bytes, base, ip) {
            starts.push(ip);
            closed = false;
        } else if closed && targets.contains(&ip) && !x86_is_padding(bytes, base, ip) {
            // A landing pad of the previous function: the code continues.
            closed = false;
        }
        match instruction.flow_control() {
            FlowControl::ConditionalBranch => {
                let target = instruction.near_branch_target();
                if !x86_is_padding(bytes, base, target) {
                    targets.insert(target);
                }
            }
            FlowControl::UnconditionalBranch => {
                let target = instruction.near_branch_target();
                if !x86_is_padding(bytes, base, target) {
                    targets.insert(target);
                }
                // A jump to its own address is an unresolved reference, one
                // that leaves the section is a tail call, and one that lands
                // on padding points at code the linker has not filled in:
                // all three end the function.
                if target == ip
                    || !(base..base + bytes.len() as u64).contains(&target)
                    || x86_is_padding(bytes, base, target)
                {
                    closed = true;
                }
            }
            FlowControl::Return | FlowControl::IndirectBranch => closed = true,
            _ => {}
        }
    }
    starts
}

fn estimate_sizes(sections: &[Section], functions: &mut BTreeMap<u64, Function>) {
    let addrs: Vec<u64> = functions.keys().copied().collect();

    for addr in &addrs {
        let Some(func) = functions.get(addr) else {
            continue;
        };
        if func.size.is_some() {
            continue;
        }
        let Some(section) = sections
            .iter()
            .find(|s| s.executable && *addr >= s.vaddr && *addr < s.vaddr.saturating_add(s.size))
        else {
            continue;
        };
        let end = addrs
            .iter()
            .copied()
            .filter(|a| *a > *addr && *a < section.vaddr.saturating_add(section.size))
            .min()
            .unwrap_or_else(|| section.vaddr.saturating_add(section.size));
        let delta = end - addr;
        if (1..=0x4000).contains(&delta) {
            let func = functions.get_mut(addr).expect("entry exists");
            func.size = Some(delta);
            func.size_estimated = true;
        }
    }
}

pub fn load(path: &Path) -> Result<Image, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let kind = object::FileKind::parse(&bytes[..]).map_err(|e| e.to_string())?;
    let file = ObjFile::parse(&bytes[..]).map_err(|e| e.to_string())?;

    let mut sections = Vec::new();
    for section in file.sections() {
        sections.push(Section {
            name: section.name().unwrap_or("<unnamed>").to_owned(),
            vaddr: section.address(),
            size: section.size(),
            file_offset: section.file_range().map(|(offset, _)| offset),
            executable: is_executable(section.kind()),
        });
    }

    // Object files keep branch targets as relocations; without them a call
    // would appear to jump into the middle of itself.
    let mut relocations = BTreeMap::new();
    for section in file.sections() {
        // Only code carries branch relocations. Data sections such as
        // `.eh_frame` also hold PC-relative relocations, and because an
        // object's sections all start at zero their offsets collide with
        // instruction addresses — a branch would then jump to the frame
        // entry instead of its own target.
        if !is_executable(section.kind()) {
            continue;
        }
        let base = section.address();
        for (offset, relocation) in section.relocations() {
            if !matches!(
                relocation.kind(),
                object::RelocationKind::Relative | object::RelocationKind::PltRelative
            ) {
                continue;
            }
            let object::RelocationTarget::Symbol(index) = relocation.target() else {
                continue;
            };
            let Ok(symbol) = file.symbol_by_index(index) else {
                continue;
            };
            if symbol.is_undefined() {
                continue;
            }
            let address = base.wrapping_add(offset);
            relocations.insert(address, symbol.address());
        }
    }

    let mut functions = BTreeMap::new();
    for sym in file.symbols() {
        if sym.kind() != object::SymbolKind::Text || sym.is_undefined() {
            continue;
        }
        upsert(
            &mut functions,
            sym.address(),
            symbol_name(&sym),
            (sym.size() > 0).then_some(sym.size()),
            NameSource::SymbolTable,
        );
    }
    for sym in file.dynamic_symbols() {
        if sym.kind() != object::SymbolKind::Text || sym.is_undefined() {
            continue;
        }
        upsert(
            &mut functions,
            sym.address(),
            symbol_name(&sym),
            (sym.size() > 0).then_some(sym.size()),
            NameSource::Dynamic,
        );
    }

    if let Ok(exports) = file.exports() {
        for export in exports.flatten() {
            let object::read::ExportTarget::Address { address } = export.target() else {
                continue;
            };
            let name = match export.name() {
                object::read::NameOrOrdinal::Name(bytes) => {
                    Some(String::from_utf8_lossy(bytes).into_owned())
                }
                object::read::NameOrOrdinal::Ordinal(_) => None,
            };
            upsert(&mut functions, address, name, None, NameSource::Dynamic);
        }
    }

    let entry = (file.entry() != 0).then(|| file.entry());
    if let Some(entry) = entry {
        upsert(
            &mut functions,
            entry,
            Some("/entry".to_owned()),
            None,
            NameSource::Entry,
        );
    }

    // Only an address inside executable memory is code a reader can lift.
    functions.retain(|address, _| {
        sections
            .iter()
            .any(|section| section.executable && *address >= section.vaddr
                && *address < section.vaddr.saturating_add(section.size))
    });
    estimate_sizes(&sections, &mut functions);

    let mut image = Image {
        format: format_of(kind),
        isa: isa_of(file.architecture()),
        entry,
        bytes,
        sections,
        functions,
        relocations,
        go: false,
    };
    image.add_go_functions();
    image.add_dwarf_functions();
    // A stripped image keeps no symbol table, so the remaining functions
    // are found by the prologues a compiler emits.
    // Only an image with nothing but a start address needs the prologue
    // scan; anything that still carries symbols, debug info or a Go
    // pclntab already lists its functions.
    if image
        .functions
        .values()
        .all(|function| function.source.iter().all(|source| *source == NameSource::Entry))
    {
        image.scan_prologues();
    }
    image.retain_code_functions();
    // An estimated extent may have covered functions the scan then found:
    // cut it at the next start and estimate again.
    let starts: Vec<u64> = image.functions.keys().copied().collect();
    for function in image.functions.values_mut() {
        if !function.size_estimated {
            continue;
        }
        let end = function.addr.saturating_add(function.size.unwrap_or(0));
        if let Some(next) = starts.iter().copied().find(|start| *start > function.addr && *start < end)
        {
            function.size = Some(next - function.addr);
        }
    }
    estimate_sizes(&image.sections, &mut image.functions);
    Ok(image)
}
