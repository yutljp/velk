//! Bounded unpacking through emulation.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::loader::{Format, Image, Isa, Section};

const MAX_STEP_LIMIT: usize = 10_000_000;
const MAX_MEMORY_LIMIT: usize = 256 << 20;
const MAX_TIME_LIMIT_MS: u64 = 60_000;
const PAGE_SIZE: u64 = 4096;

/// Bounds and optional stop address for emulation based unpacking.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Options {
    /// Stop before executing this virtual address.
    pub stop_address: Option<String>,
    /// Maximum number of executed IR statements.
    pub step_limit: usize,
    /// Limit for distinct bytes written and mapped bytes saved.
    pub memory_limit: usize,
    /// Maximum elapsed milliseconds.
    pub time_limit_ms: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            stop_address: None,
            step_limit: 1_000_000,
            memory_limit: 64 << 20,
            time_limit_ms: 5_000,
        }
    }
}

/// A contiguous virtual address range involved in unpacking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Region {
    /// First address in hexadecimal.
    pub address: String,
    /// Number of bytes in the region.
    pub size: u64,
}

/// Outcome of an emulation based unpacking run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Entry address used for emulation.
    pub entry: String,
    /// Entry address of the recovered image, when unpacking was observed.
    pub new_entry: Option<String>,
    /// Number of executed IR statements.
    pub steps: usize,
    /// Why emulation stopped.
    pub stop_reason: String,
    /// Explanation when emulation stopped with an error.
    pub error: Option<String>,
    /// Whether unpacked code was reached.
    pub status: String,
    /// Mapped load regions in the input image.
    pub mapped_regions: Vec<Region>,
    /// Mapped regions that received writes.
    pub written_regions: Vec<Region>,
    /// Mapped regions reached during execution.
    pub executed_regions: Vec<Region>,
    /// Whether a written address was reached.
    pub unpacked: bool,
}

pub(crate) struct Output {
    pub report: Report,
    pub elf: Option<Vec<u8>>,
}

pub(crate) fn run_image(image: &Image, options: &Options) -> Result<Output> {
    if image.format != Format::Elf {
        return Err(Error::Emulation(
            "emulation based unpacking currently requires a Linux ELF image".to_owned(),
        ));
    }
    if image.load_segments.is_empty() {
        return Err(Error::Emulation(
            "ELF image has no mapped load regions".to_owned(),
        ));
    }
    if options.step_limit > MAX_STEP_LIMIT {
        return Err(Error::Emulation(format!(
            "stepLimit exceeds {MAX_STEP_LIMIT}"
        )));
    }
    if options.memory_limit > MAX_MEMORY_LIMIT {
        return Err(Error::Emulation(format!(
            "memoryLimit exceeds {MAX_MEMORY_LIMIT} bytes"
        )));
    }
    if options.time_limit_ms > MAX_TIME_LIMIT_MS {
        return Err(Error::Emulation(format!(
            "timeLimitMs exceeds {MAX_TIME_LIMIT_MS}"
        )));
    }
    let mapped_size = image
        .load_segments
        .iter()
        .filter(|section| section.loaded && section.size != 0)
        .try_fold(0usize, |total, section| {
            usize::try_from(section.size)
                .ok()
                .and_then(|size| total.checked_add(size))
        });
    let Some(mapped_size) = mapped_size else {
        return Err(Error::Emulation("mapped image size overflows".to_owned()));
    };
    if mapped_size > options.memory_limit || mapped_size > MAX_MEMORY_LIMIT {
        return Err(Error::Emulation(format!(
            "mapped image exceeds the {}-byte unpacking memory limit",
            options.memory_limit
        )));
    }
    let Some(entry) = image.entry else {
        return Err(Error::Emulation("ELF image has no entry point".to_owned()));
    };
    let (heap_start, heap_end) = match crate::emulation::Memory::heap_range_for_unpack(image) {
        Ok(range) => range,
        Err(error) => return Err(Error::Emulation(error)),
    };
    if !image
        .section_at(entry)
        .is_some_and(|section| section.executable)
    {
        return Err(Error::Emulation(
            "ELF entry point is not in an executable region".to_owned(),
        ));
    }
    if let Some(stop) = &options.stop_address {
        let Some(address) = crate::addr::parse(stop) else {
            return Err(Error::Emulation(format!("invalid stop address: {stop}")));
        };
        if !image
            .section_at(address)
            .is_some_and(|section| section.loaded)
            && !(address >= heap_start && address < heap_end)
        {
            return Err(Error::Emulation(format!(
                "stop address {stop} is outside mapped image regions"
            )));
        }
    }

    let emulation_options = crate::emulation::Options {
        step_limit: options.step_limit,
        time_limit_ms: options.time_limit_ms,
        skip_calls: true,
        ..Default::default()
    };
    let run =
        match crate::ir::eval::emulation::run_for_unpack(image, entry, &emulation_options, options)
        {
            Ok(run) => run,
            Err(error) => return Err(error),
        };
    let unpacked = matches!(
        run.reason.as_str(),
        "requested address" | "written code reached"
    );
    let stop_address = crate::addr::parse(&run.address);
    if unpacked
        && stop_address.is_none_or(|address| {
            !in_regions(address, &image.load_segments)
                && !(address >= heap_start && address < heap_end)
        })
    {
        return Err(Error::Emulation(format!(
            "reached code outside the image and bounded heap at {}",
            run.address
        )));
    }
    let extra_segments = heap_segments(
        &run.written_regions,
        heap_start,
        heap_end,
        stop_address.filter(|_| unpacked),
    );
    let mut mapped = image
        .load_segments
        .iter()
        .filter(|section| section.loaded && section.size != 0)
        .map(|section| (section.vaddr, section.size))
        .collect::<Vec<_>>();
    mapped.extend(
        extra_segments
            .iter()
            .map(|section| (section.vaddr, section.size)),
    );
    let mapped_regions = to_regions(merge_ranges(mapped));
    let mut written = Vec::new();
    for (address, size) in &run.written_regions {
        let Some(end) = address.checked_add(*size) else {
            continue;
        };
        for section in &image.load_segments {
            if let Some(range) = intersect(*address, end, section.vaddr, section.size) {
                written.push(range);
            }
        }
        if let Some(range) = intersect(*address, end, heap_start, heap_end - heap_start) {
            written.push(range);
        }
    }
    let written_regions = to_regions(merge_ranges(written));
    let mut executed = image
        .load_segments
        .iter()
        .filter(|section| {
            run.executed_addresses
                .iter()
                .any(|address| contains(section.vaddr, section.size, *address))
                || stop_address.is_some_and(|address| {
                    unpacked && contains(section.vaddr, section.size, address)
                })
        })
        .map(|section| (section.vaddr, section.size))
        .collect::<Vec<_>>();
    executed.extend(extra_segments.iter().filter_map(|section| {
        let reached = run
            .executed_addresses
            .iter()
            .any(|address| contains(section.vaddr, section.size, *address))
            || stop_address
                .is_some_and(|address| unpacked && contains(section.vaddr, section.size, address));
        reached.then_some((section.vaddr, section.size))
    }));
    let executed_regions = to_regions(merge_ranges(executed));
    let new_entry = unpacked.then(|| run.address.clone());
    let report = Report {
        entry: crate::addr::format(entry),
        new_entry,
        steps: run.steps,
        stop_reason: run.reason.clone(),
        error: run.error.clone(),
        status: if unpacked {
            "unpacked".to_owned()
        } else {
            "no unpacking observed".to_owned()
        },
        mapped_regions,
        written_regions,
        executed_regions,
        unpacked,
    };
    let elf = if unpacked {
        let Some(entry) = crate::addr::parse(&run.address) else {
            return Err(Error::Emulation(format!(
                "invalid emulation stop address: {}",
                run.address
            )));
        };
        let rebuilt = match rebuild_elf(
            image,
            &run.memory,
            entry,
            &extra_segments,
            options.memory_limit,
        ) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        Some(rebuilt)
    } else {
        None
    };
    Ok(Output { report, elf })
}

fn rebuild_elf(
    image: &Image,
    changes: &[crate::emulation::MemoryChange],
    entry: u64,
    extra_segments: &[Section],
    limit: usize,
) -> Result<Vec<u8>> {
    // Any failed field write or conversion makes the rebuilt ELF invalid, so stop the rebuild.
    let (is_64, machine) = match image.isa {
        Isa::X86_64 => (true, 62u16),
        Isa::I386 => (false, 3u16),
        Isa::AArch64 => (true, 183u16),
        _ => {
            return Err(Error::Emulation(format!(
                "unsupported ELF architecture: {}",
                image.isa
            )));
        }
    };
    let header_size = if is_64 { 64usize } else { 52usize };
    let program_header_size = if is_64 { 56usize } else { 32usize };
    let mut segments: Vec<Section> = image
        .load_segments
        .iter()
        .filter(|section| section.loaded && section.size != 0)
        .cloned()
        .collect();
    if segments.is_empty() {
        return Err(Error::Emulation(
            "ELF image has no nonempty mapped load regions".to_owned(),
        ));
    }
    segments.extend_from_slice(extra_segments);
    segments.sort_by_key(|section| section.vaddr);
    if segments.len() > usize::from(u16::MAX) {
        return Err(Error::Emulation(
            "ELF has too many mapped regions".to_owned(),
        ));
    }
    let total_memory = segments.iter().try_fold(0usize, |total, section| {
        usize::try_from(section.size)
            .ok()
            .and_then(|size| total.checked_add(size))
    });
    let Some(total_memory) = total_memory else {
        return Err(Error::Emulation("mapped image size overflows".to_owned()));
    };
    if total_memory > limit || total_memory > MAX_MEMORY_LIMIT {
        return Err(Error::Emulation(format!(
            "mapped image exceeds the {limit}-byte unpacking memory limit"
        )));
    }
    let phnum = segments.len();
    let phdr_end = match header_size
        .checked_add(program_header_size.saturating_mul(phnum))
        .ok_or_else(|| Error::Emulation("ELF header size overflows".to_owned()))
    {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let use_header_segment = segments[0].vaddr >= PAGE_SIZE
        && !segments.iter().any(|section| {
            section.vaddr <= segments[0].vaddr - PAGE_SIZE
                && section.vaddr.saturating_add(section.size) > segments[0].vaddr - PAGE_SIZE
        });
    if !use_header_segment && phdr_end as u64 > segments[0].size {
        return Err(Error::Emulation(
            "first mapped region is too small for the ELF program headers".to_owned(),
        ));
    }
    let Some(output_phnum) = phnum.checked_add(usize::from(use_header_segment)) else {
        return Err(Error::Emulation(
            "ELF program header count overflows".to_owned(),
        ));
    };
    if output_phnum > usize::from(u16::MAX) {
        return Err(Error::Emulation(
            "ELF has too many program headers to save".to_owned(),
        ));
    }
    let mut output = vec![0u8; PAGE_SIZE as usize];
    let mut offsets = Vec::with_capacity(output_phnum);
    if use_header_segment {
        offsets.push(0u64);
    }
    for (index, section) in segments.iter().enumerate() {
        let offset = if !use_header_segment && index == 0 {
            0
        } else {
            match align_up(output.len() as u64, PAGE_SIZE)
                .ok_or_else(|| Error::Emulation("ELF output size overflows".to_owned()))
            {
                Ok(value) => value,
                Err(error) => return Err(error),
            }
        };
        let offset_usize = match usize::try_from(offset)
            .map_err(|_| Error::Emulation("ELF output exceeds the host address space".to_owned()))
        {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let size = match usize::try_from(section.size).map_err(|_| {
            Error::Emulation("mapped region exceeds the host address space".to_owned())
        }) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        let end = match offset_usize
            .checked_add(size)
            .ok_or_else(|| Error::Emulation("ELF output size overflows".to_owned()))
        {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        if end > limit.saturating_add(PAGE_SIZE as usize) {
            return Err(Error::Emulation(
                "ELF output exceeds the unpacking memory limit".to_owned(),
            ));
        }
        output.resize(end, 0);
        if let Some(file_offset) = section.file_offset {
            let file_size = match usize::try_from(section.file_size.min(section.size))
                .map_err(|_| Error::Emulation("mapped file range is too large".to_owned()))
            {
                Ok(value) => value,
                Err(error) => return Err(error),
            };
            if let Some(bytes) = image.read(file_offset, file_size as u64) {
                output[offset_usize..offset_usize + file_size].copy_from_slice(bytes);
            } else {
                return Err(Error::Emulation(format!(
                    "mapped region at 0x{:x} has unavailable input bytes",
                    section.vaddr
                )));
            }
        }
        offsets.push(offset);
    }
    for change in changes {
        let Some(address) = crate::addr::parse(&change.address) else {
            return Err(Error::Emulation(format!(
                "invalid written address in emulator report: {}",
                change.address
            )));
        };
        for (index, byte) in change.bytes.iter().enumerate() {
            let Some(at) = address.checked_add(index as u64) else {
                break;
            };
            let Some(section_index) = segments.iter().position(|section| {
                at >= section.vaddr && at.saturating_sub(section.vaddr) < section.size
            }) else {
                continue;
            };
            let offset = usize::try_from(offsets[section_index + usize::from(use_header_segment)])
                .ok()
                .and_then(|offset| {
                    usize::try_from(at - segments[section_index].vaddr)
                        .ok()
                        .and_then(|displacement| offset.checked_add(displacement))
                });
            if let Some(offset) = offset
                && let Some(destination) = output.get_mut(offset)
            {
                *destination = *byte;
            }
        }
    }
    let mut program_index = 0usize;
    if use_header_segment {
        if let Err(error) = write_program_header(
            &mut output,
            ProgramHeader {
                is_64,
                index: program_index,
                offset: 0,
                address: segments[0].vaddr - PAGE_SIZE,
                file_size: PAGE_SIZE,
                memory_size: PAGE_SIZE,
                flags: 4,
            },
        ) {
            return Err(error);
        }
        program_index += 1;
    }
    for (index, section) in segments.iter().enumerate() {
        let offset_index = index + usize::from(use_header_segment);
        let flags =
            4 | if section.read_only { 0 } else { 2 } | if section.executable { 1 } else { 0 };
        if let Err(error) = write_program_header(
            &mut output,
            ProgramHeader {
                is_64,
                index: program_index,
                offset: offsets[offset_index],
                address: section.vaddr,
                file_size: section.size,
                memory_size: section.size,
                flags,
            },
        ) {
            return Err(error);
        }
        program_index += 1;
    }
    let symbol_data = match symbol_table(image, is_64) {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let mut section_names = vec![0];
    let mut mapped_names = Vec::with_capacity(output_phnum);
    for index in 0..output_phnum {
        let name = if use_header_segment && index == 0 {
            ".headers".to_owned()
        } else {
            let input_index = index - usize::from(use_header_segment);
            let section = &segments[input_index];
            let name = if section.executable {
                "text"
            } else if !section.read_only {
                "data"
            } else {
                "rodata"
            };
            format!(".{name}{input_index}")
        };
        let name_offset = match add_string(&mut section_names, &name) {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        mapped_names.push(name_offset);
    }
    let symbol_name = match add_string(&mut section_names, ".symtab") {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let string_name = match add_string(&mut section_names, ".strtab") {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let names_name = match add_string(&mut section_names, ".shstrtab") {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let symbol_offset = match align_up(output.len() as u64, if is_64 { 8 } else { 4 })
        .ok_or_else(|| Error::Emulation("ELF symbol table offset overflows".to_owned()))
    {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    output.resize(symbol_offset as usize, 0);
    output.extend_from_slice(&symbol_data.0);
    let string_offset = output.len() as u64;
    output.extend_from_slice(&symbol_data.1);
    let section_names_offset = output.len() as u64;
    output.extend_from_slice(&section_names);
    let section_header_size = if is_64 { 64usize } else { 40usize };
    let section_count = match output_phnum
        .checked_add(4)
        .ok_or_else(|| Error::Emulation("ELF section count overflows".to_owned()))
    {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let section_header_offset = match align_up(output.len() as u64, if is_64 { 8 } else { 4 })
        .ok_or_else(|| Error::Emulation("ELF section table offset overflows".to_owned()))
    {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    let section_table_end = match section_header_offset
        .checked_add((section_header_size * section_count) as u64)
        .ok_or_else(|| Error::Emulation("ELF section table size overflows".to_owned()))
    {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    if section_table_end > (limit as u64).saturating_add(PAGE_SIZE) {
        return Err(Error::Emulation(
            "ELF output exceeds the unpacking memory limit".to_owned(),
        ));
    }
    output.resize(section_table_end as usize, 0);
    for index in 0..output_phnum {
        let (address, offset, size, flags) = if use_header_segment && index == 0 {
            (segments[0].vaddr - PAGE_SIZE, 0, PAGE_SIZE, 2)
        } else {
            let input_index = index - usize::from(use_header_segment);
            let section = &segments[input_index];
            let flags =
                2 | if section.read_only { 0 } else { 1 } | if section.executable { 4 } else { 0 };
            (section.vaddr, offsets[index], section.size, flags)
        };
        if let Err(error) = write_section_header(
            &mut output,
            SectionHeader {
                is_64,
                table_offset: section_header_offset,
                index: index + 1,
                name: mapped_names[index],
                kind: 1,
                flags,
                address,
                offset,
                size,
                link: 0,
                info: 0,
                alignment: PAGE_SIZE,
                entry_size: 0,
            },
        ) {
            return Err(error);
        }
    }
    let symbol_index = output_phnum + 1;
    let string_index = output_phnum + 2;
    let names_index = output_phnum + 3;
    if let Err(error) = write_section_header(
        &mut output,
        SectionHeader {
            is_64,
            table_offset: section_header_offset,
            index: symbol_index,
            name: symbol_name,
            kind: 2,
            flags: 0,
            address: 0,
            offset: symbol_offset,
            size: symbol_data.0.len() as u64,
            link: string_index as u32,
            info: 1,
            alignment: if is_64 { 8 } else { 4 },
            entry_size: if is_64 { 24 } else { 16 },
        },
    ) {
        return Err(error);
    }
    if let Err(error) = write_section_header(
        &mut output,
        SectionHeader {
            is_64,
            table_offset: section_header_offset,
            index: string_index,
            name: string_name,
            kind: 3,
            flags: 0,
            address: 0,
            offset: string_offset,
            size: symbol_data.1.len() as u64,
            link: 0,
            info: 0,
            alignment: 1,
            entry_size: 0,
        },
    ) {
        return Err(error);
    }
    if let Err(error) = write_section_header(
        &mut output,
        SectionHeader {
            is_64,
            table_offset: section_header_offset,
            index: names_index,
            name: names_name,
            kind: 3,
            flags: 0,
            address: 0,
            offset: section_names_offset,
            size: section_names.len() as u64,
            link: 0,
            info: 0,
            alignment: 1,
            entry_size: 0,
        },
    ) {
        return Err(error);
    }
    if let Err(error) = write_elf_header(
        &mut output,
        ElfHeader {
            is_64,
            machine,
            entry,
            program_header_count: output_phnum,
            header_size,
            program_header_size,
            section_header_offset,
            section_header_size,
            section_count,
            section_names_index: names_index,
        },
    ) {
        return Err(error);
    }
    Ok(output)
}

fn symbol_table(image: &Image, is_64: bool) -> Result<(Vec<u8>, Vec<u8>)> {
    const MAX_SYMBOLS: usize = 1 << 20;
    let mut names = std::collections::BTreeSet::new();
    for function in image.functions.values() {
        if let Some(name) = &function.name
            && !name.is_empty()
            && !name.contains('\0')
        {
            names.insert((
                function.addr,
                function.size.unwrap_or(0),
                0x12u8,
                name.clone(),
            ));
        }
        for name in &function.aliases {
            if !name.is_empty() && !name.contains('\0') {
                names.insert((
                    function.addr,
                    function.size.unwrap_or(0),
                    0x12u8,
                    name.clone(),
                ));
            }
        }
    }
    for (address, name) in &image.data_symbols {
        if !name.is_empty() && !name.contains('\0') {
            names.insert((*address, 0u64, 0x11u8, name.clone()));
        }
    }
    if names.len() > MAX_SYMBOLS {
        return Err(Error::Emulation(
            "image has too many symbols to save".to_owned(),
        ));
    }
    let entry_size = if is_64 { 24usize } else { 16usize };
    let mut table = vec![0u8; entry_size];
    let mut strings = vec![0u8];
    for (address, size, info, name) in names {
        let name_offset = match u32::try_from(strings.len())
            .map_err(|_| Error::Emulation("ELF string table exceeds 4 GiB".to_owned()))
        {
            Ok(value) => value,
            Err(error) => return Err(error),
        };
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        let start = table.len();
        table.resize(start + entry_size, 0);
        let mut fields = Fields::at(&mut table, start);
        fields.u32(0, name_offset);
        if is_64 {
            fields.bytes(4, &[info]);
            fields.u16(6, 0xfff1);
            fields.u64(8, address);
            fields.u64(16, size);
        } else {
            fields.narrow32(4, address, "ELF32 symbol address exceeds 32 bits");
            fields.narrow32(8, size, "ELF32 symbol size exceeds 32 bits");
            fields.bytes(12, &[info]);
            fields.u16(14, 0xfff1);
        }
        if let Err(error) = fields.result {
            return Err(error);
        }
    }
    Ok((table, strings))
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
}

fn add_string(table: &mut Vec<u8>, value: &str) -> Result<u32> {
    let offset = match u32::try_from(table.len())
        .map_err(|_| Error::Emulation("ELF section name table exceeds 4 GiB".to_owned()))
    {
        Ok(value) => value,
        Err(error) => return Err(error),
    };
    table.extend_from_slice(value.as_bytes());
    table.push(0);
    Ok(offset)
}

struct ElfHeader {
    is_64: bool,
    machine: u16,
    entry: u64,
    program_header_count: usize,
    header_size: usize,
    program_header_size: usize,
    section_header_offset: u64,
    section_header_size: usize,
    section_count: usize,
    section_names_index: usize,
}

struct SectionHeader {
    is_64: bool,
    table_offset: u64,
    index: usize,
    name: u32,
    kind: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    alignment: u64,
    entry_size: u64,
}

struct ProgramHeader {
    is_64: bool,
    index: usize,
    offset: u64,
    address: u64,
    file_size: u64,
    memory_size: u64,
    flags: u32,
}

/// Little-endian fields written at offsets from `base`. The first write that
/// fails is kept and later ones do nothing.
struct Fields<'a> {
    output: &'a mut [u8],
    base: usize,
    result: Result<()>,
}

impl<'a> Fields<'a> {
    fn at(output: &'a mut [u8], base: usize) -> Self {
        Self {
            output,
            base,
            result: Ok(()),
        }
    }

    fn bytes(&mut self, offset: usize, bytes: &[u8]) {
        if self.result.is_err() {
            return;
        }
        self.result = match self.base.checked_add(offset) {
            Some(offset) => put(self.output, offset, bytes),
            None => Err(Error::Emulation("ELF field offset overflows".to_owned())),
        };
    }

    fn u16(&mut self, offset: usize, value: u16) {
        self.bytes(offset, &value.to_le_bytes());
    }

    fn u32(&mut self, offset: usize, value: u32) {
        self.bytes(offset, &value.to_le_bytes());
    }

    fn u64(&mut self, offset: usize, value: u64) {
        self.bytes(offset, &value.to_le_bytes());
    }

    /// Writes `value` in 16 bits, or fails with `message` when it needs more.
    fn narrow16(&mut self, offset: usize, value: usize, message: &str) {
        match u16::try_from(value) {
            Ok(value) => self.u16(offset, value),
            Err(_) => self.fail(message),
        }
    }

    /// Writes `value` in 32 bits, or fails with `message` when it needs more.
    fn narrow32(&mut self, offset: usize, value: u64, message: &str) {
        match u32::try_from(value) {
            Ok(value) => self.u32(offset, value),
            Err(_) => self.fail(message),
        }
    }

    fn fail(&mut self, message: &str) {
        if self.result.is_ok() {
            self.result = Err(Error::Emulation(message.to_owned()));
        }
    }
}

fn write_elf_header(output: &mut [u8], header: ElfHeader) -> Result<()> {
    let ElfHeader {
        is_64,
        machine,
        entry,
        program_header_count: phnum,
        header_size,
        program_header_size,
        section_header_offset,
        section_header_size,
        section_count,
        section_names_index,
    } = header;
    let Some(ident) = output.get_mut(..16) else {
        return Err(Error::Emulation(
            "ELF output header is truncated".to_owned(),
        ));
    };
    ident[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', if is_64 { 2 } else { 1 }, 1, 1]);
    let mut fields = Fields::at(output, 0);
    fields.u16(16, 2);
    fields.u16(18, machine);
    fields.u32(20, 1);
    // The offset of the sizes and counts that end the header.
    let tail = if is_64 {
        fields.u64(24, entry);
        fields.u64(32, 64);
        fields.u64(40, section_header_offset);
        48
    } else {
        fields.narrow32(24, entry, "ELF32 entry exceeds 32 bits");
        fields.u32(28, 52);
        fields.narrow32(
            32,
            section_header_offset,
            "ELF32 section table exceeds 32 bits",
        );
        36
    };
    fields.u32(tail, 0);
    fields.u16(tail + 4, header_size as u16);
    fields.u16(tail + 6, program_header_size as u16);
    fields.u16(tail + 8, phnum as u16);
    fields.u16(tail + 10, section_header_size as u16);
    fields.narrow16(tail + 12, section_count, "ELF section count exceeds 65535");
    fields.narrow16(
        tail + 14,
        section_names_index,
        "ELF section name index exceeds 65535",
    );
    fields.result
}

fn write_section_header(output: &mut [u8], header: SectionHeader) -> Result<()> {
    let SectionHeader {
        is_64,
        table_offset,
        index,
        name,
        kind,
        flags,
        address,
        offset,
        size,
        link,
        info,
        alignment,
        entry_size,
    } = header;
    let header_size = if is_64 { 64usize } else { 40usize };
    let Ok(table_offset) = usize::try_from(table_offset) else {
        return Err(Error::Emulation(
            "ELF section header offset exceeds the host address space".to_owned(),
        ));
    };
    let Some(base) = index
        .checked_mul(header_size)
        .and_then(|offset| table_offset.checked_add(offset))
    else {
        return Err(Error::Emulation(
            "ELF section header offset overflows".to_owned(),
        ));
    };
    let mut fields = Fields::at(output, base);
    fields.u32(0, name);
    fields.u32(4, kind);
    if is_64 {
        fields.u64(8, flags);
        fields.u64(16, address);
        fields.u64(24, offset);
        fields.u64(32, size);
        fields.u32(40, link);
        fields.u32(44, info);
        fields.u64(48, alignment);
        fields.u64(56, entry_size);
    } else {
        fields.narrow32(8, flags, "ELF32 section flags exceed 32 bits");
        fields.narrow32(12, address, "ELF32 section address exceeds 32 bits");
        fields.narrow32(16, offset, "ELF32 section offset exceeds 32 bits");
        fields.narrow32(20, size, "ELF32 section size exceeds 32 bits");
        fields.u32(24, link);
        fields.u32(28, info);
        fields.narrow32(32, alignment, "ELF32 section alignment exceeds 32 bits");
        fields.narrow32(36, entry_size, "ELF32 symbol size exceeds 32 bits");
    }
    fields.result
}

fn write_program_header(output: &mut [u8], header: ProgramHeader) -> Result<()> {
    let ProgramHeader {
        is_64,
        index,
        offset,
        address,
        file_size,
        memory_size,
        flags,
    } = header;
    let size = if is_64 { 56usize } else { 32usize };
    let header_size = if is_64 { 64usize } else { 52usize };
    let Some(base) = index
        .checked_mul(size)
        .and_then(|offset| header_size.checked_add(offset))
    else {
        return Err(Error::Emulation(
            "ELF program header offset overflows".to_owned(),
        ));
    };
    let mut fields = Fields::at(output, base);
    fields.u32(0, 1);
    if is_64 {
        fields.u32(4, flags);
        fields.u64(8, offset);
        fields.u64(16, address);
        fields.u64(24, address);
        fields.u64(32, file_size);
        fields.u64(40, memory_size);
        fields.u64(48, PAGE_SIZE);
    } else {
        fields.narrow32(4, offset, "ELF32 file offset exceeds 32 bits");
        fields.narrow32(8, address, "ELF32 address exceeds 32 bits");
        fields.narrow32(12, address, "ELF32 address exceeds 32 bits");
        fields.narrow32(16, file_size, "ELF32 segment exceeds 32 bits");
        fields.narrow32(20, memory_size, "ELF32 segment exceeds 32 bits");
        fields.u32(24, flags);
        fields.u32(28, PAGE_SIZE as u32);
    }
    fields.result
}

fn put(output: &mut [u8], offset: usize, bytes: &[u8]) -> Result<()> {
    let Some(end) = offset.checked_add(bytes.len()) else {
        return Err(Error::Emulation("ELF field offset overflows".to_owned()));
    };
    let Some(destination) = output.get_mut(offset..end) else {
        return Err(Error::Emulation(
            "ELF header does not fit the output".to_owned(),
        ));
    };
    destination.copy_from_slice(bytes);
    Ok(())
}

fn contains(start: u64, size: u64, address: u64) -> bool {
    address >= start && address.saturating_sub(start) < size
}

fn in_regions(address: u64, regions: &[Section]) -> bool {
    regions
        .iter()
        .any(|region| region.loaded && contains(region.vaddr, region.size, address))
}

fn intersect(start: u64, end: u64, region_start: u64, region_size: u64) -> Option<(u64, u64)> {
    let Some(region_end) = region_start.checked_add(region_size) else {
        return None;
    };
    let overlap_start = start.max(region_start);
    let overlap_end = end.min(region_end);
    (overlap_start < overlap_end).then(|| (overlap_start, overlap_end - overlap_start))
}

fn heap_segments(
    written_regions: &[(u64, u64)],
    heap_start: u64,
    heap_end: u64,
    entry: Option<u64>,
) -> Vec<Section> {
    let mut pages = BTreeSet::new();
    for (address, size) in written_regions {
        let Some(end) = address.checked_add(*size) else {
            continue;
        };
        let Some((start, size)) = intersect(*address, end, heap_start, heap_end - heap_start)
        else {
            continue;
        };
        let Some(end) = start.checked_add(size) else {
            continue;
        };
        let mut page = start & !(PAGE_SIZE - 1);
        while page < end {
            pages.insert(page);
            let Some(next) = page.checked_add(PAGE_SIZE) else {
                break;
            };
            page = next;
        }
    }
    if let Some(entry) = entry
        && entry >= heap_start
        && entry < heap_end
    {
        pages.insert(entry & !(PAGE_SIZE - 1));
    }

    let mut regions: Vec<(u64, u64)> = Vec::new();
    for page in pages {
        if let Some((start, size)) = regions.last_mut()
            && start.saturating_add(*size) == page
        {
            *size = size.saturating_add(PAGE_SIZE);
        } else {
            regions.push((page, PAGE_SIZE));
        }
    }
    regions
        .into_iter()
        .map(|(vaddr, size)| Section {
            name: "unpacked".to_owned(),
            vaddr,
            size,
            file_offset: None,
            file_size: 0,
            executable: true,
            loaded: true,
            read_only: false,
        })
        .collect()
}

fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.retain(|(_, size)| *size != 0);
    ranges.sort_by_key(|(start, _)| *start);
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, size) in ranges {
        let Some(end) = start.checked_add(size) else {
            continue;
        };
        if let Some((last_start, last_size)) = merged.last_mut()
            && start <= last_start.saturating_add(*last_size)
        {
            *last_size = (*last_start + *last_size).max(end) - *last_start;
        } else {
            merged.push((start, size));
        }
    }
    merged
}

fn to_regions(ranges: Vec<(u64, u64)>) -> Vec<Region> {
    ranges
        .into_iter()
        .map(|(address, size)| Region {
            address: crate::addr::format(address),
            size,
        })
        .collect()
}
