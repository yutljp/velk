//! Writing the memory of an unpacked Windows image back as a PE file.

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::loader::{Image, Section};

const SECTION_HEADER: usize = 40;
/// Code that is read, written and executed.
const WRITTEN_CODE: u32 = 0xe000_0020;

fn failed<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Emulation(message.into()))
}

fn word(bytes: &[u8], offset: usize, width: usize) -> Result<u64> {
    let Some(field) = offset
        .checked_add(width)
        .and_then(|end| bytes.get(offset..end))
    else {
        return failed("PE header is truncated");
    };
    let mut value = [0u8; 8];
    value[..width].copy_from_slice(field);
    Ok(u64::from_le_bytes(value))
}

fn put(bytes: &mut [u8], offset: usize, value: u64, width: usize) -> Result<()> {
    let Some(field) = offset
        .checked_add(width)
        .and_then(|end| bytes.get_mut(offset..end))
    else {
        return failed("PE header is truncated");
    };
    field.copy_from_slice(&value.to_le_bytes()[..width]);
    Ok(())
}

fn align(value: u64, alignment: u64) -> Result<u64> {
    if alignment == 0 {
        return failed("PE alignment is zero");
    }
    match value.checked_next_multiple_of(alignment) {
        Some(aligned) => Ok(aligned),
        None => failed("PE output size overflows"),
    }
}

/// The input's headers and sections with the bytes memory held when
/// emulation stopped, `entry` as the entry point, and one further section
/// for each of `extra`, the regions written outside the image. A word of
/// memory that holds the address of one of `exports`, each named
/// `dll!function`, is an import the program resolved while it ran: these
/// become an import table in a section of their own.
pub(super) fn rebuild(
    image: &Image,
    changes: &[crate::emulation::MemoryChange],
    entry: u64,
    extra: &[Section],
    exports: &BTreeMap<u64, String>,
    limit: usize,
) -> Result<Vec<u8>> {
    let input = image.input();
    let pe = match word(input, 0x3c, 4) {
        Ok(offset) => offset as usize,
        Err(error) => return Err(error),
    };
    if input.get(pe..pe.saturating_add(4)) != Some(b"PE\0\0") {
        return failed("PE signature is missing");
    }
    let field = |offset: usize, width: usize| word(input, offset, width);
    let (count, optional_size) = match (field(pe + 6, 2), field(pe + 20, 2)) {
        (Ok(count), Ok(size)) => (count as usize, size as usize),
        (Err(error), _) | (_, Err(error)) => return Err(error),
    };
    let optional = pe + 24;
    let wide = match field(optional, 2) {
        Ok(0x10b) => false,
        Ok(0x20b) => true,
        Ok(_) => return failed("PE optional header has an unknown format"),
        Err(error) => return Err(error),
    };
    let base = match if wide {
        field(optional + 24, 8)
    } else {
        field(optional + 28, 4)
    } {
        Ok(base) => base,
        Err(error) => return Err(error),
    };
    let (section_alignment, file_alignment, headers_size) = match (
        field(optional + 32, 4),
        field(optional + 36, 4),
        field(optional + 60, 4),
    ) {
        (Ok(section), Ok(file), Ok(headers)) => (section, file, headers),
        (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => return Err(error),
    };
    let table = optional + optional_size;
    let Some(table_end) = count
        .checked_add(extra.len())
        .and_then(|sections| sections.checked_mul(SECTION_HEADER))
        .and_then(|size| table.checked_add(size))
    else {
        return failed("PE section table overflows");
    };
    if count
        .checked_add(extra.len())
        .is_none_or(|sections| sections > 96)
        || table_end as u64 > headers_size
        || headers_size as usize > input.len()
    {
        return failed("PE headers have no room for the section table");
    }
    let Some(entry) = entry
        .checked_sub(base)
        .filter(|entry| u32::try_from(*entry).is_ok())
    else {
        return failed("unpacked entry point is outside what the PE image can address");
    };
    let mut output = input[..headers_size as usize].to_vec();
    // Where each section's bytes are in memory and in the output.
    let mut placed: Vec<(u64, u64, usize)> = Vec::new();
    let mut image_end = 0u64;
    for index in 0..count + extra.len() {
        let header = table + index * SECTION_HEADER;
        let (rva, size, initialized) = if index < count {
            let fields = (
                field(header + 8, 4),
                field(header + 12, 4),
                field(header + 16, 4),
                field(header + 20, 4),
            );
            let (virtual_size, rva, raw_size, raw_offset) = match fields {
                (Ok(virtual_size), Ok(rva), Ok(raw_size), Ok(raw_offset)) => {
                    (virtual_size, rva, raw_size, raw_offset)
                }
                (Err(error), _, _, _)
                | (_, Err(error), _, _)
                | (_, _, Err(error), _)
                | (_, _, _, Err(error)) => return Err(error),
            };
            let size = if virtual_size == 0 {
                raw_size
            } else {
                virtual_size
            };
            let kept = raw_size.min(size) as usize;
            let initialized = if kept == 0 {
                &[][..]
            } else {
                match (raw_offset as usize)
                    .checked_add(kept)
                    .and_then(|end| input.get(raw_offset as usize..end))
                {
                    Some(bytes) => bytes,
                    None => return failed("PE section data is outside the file"),
                }
            };
            (rva, size, initialized)
        } else {
            let region = &extra[index - count];
            let Some(rva) = region
                .vaddr
                .checked_sub(base)
                .filter(|rva| *rva >= image_end && u32::try_from(*rva).is_ok())
            else {
                return failed(format!(
                    "written code at 0x{:x} is outside what the PE image can address",
                    region.vaddr
                ));
            };
            if rva % section_alignment != 0 {
                return failed(format!(
                    "written code at 0x{:x} does not start on a section boundary",
                    region.vaddr
                ));
            }
            (rva, region.size, &[][..])
        };
        let (offset, raw_size) = match (
            align(output.len() as u64, file_alignment),
            align(size, file_alignment),
        ) {
            (Ok(offset), Ok(raw_size)) => (offset, raw_size),
            (Err(error), _) | (_, Err(error)) => return Err(error),
        };
        let Some(end) = offset
            .checked_add(raw_size)
            .filter(|end| *end <= (limit as u64).saturating_add(headers_size))
            .filter(|_| u32::try_from(size).is_ok())
        else {
            return failed("PE output exceeds the unpacking memory limit");
        };
        output.resize(end as usize, 0);
        output[offset as usize..offset as usize + initialized.len()].copy_from_slice(initialized);
        let written = [
            put(&mut output, header + 8, size, 4),
            put(&mut output, header + 12, rva, 4),
            put(&mut output, header + 16, raw_size, 4),
            put(
                &mut output,
                header + 20,
                if raw_size == 0 { 0 } else { offset },
                4,
            ),
        ];
        if let Some(Err(error)) = written.into_iter().find(Result::is_err) {
            return Err(error);
        }
        if index >= count {
            let mut name = [0u8; 8];
            let text = format!(".velk{}", index - count);
            name[..text.len().min(8)].copy_from_slice(&text.as_bytes()[..text.len().min(8)]);
            output[header..header + 8].copy_from_slice(&name);
            output[header + 24..header + 36].fill(0);
            if let Err(error) = put(&mut output, header + 36, u64::from(WRITTEN_CODE), 4) {
                return Err(error);
            }
        }
        let Some(start) = base.checked_add(rva) else {
            return failed("PE section address overflows");
        };
        placed.push((start, size, offset as usize));
        image_end = match align(rva.saturating_add(size), section_alignment) {
            Ok(end) => end.max(image_end),
            Err(error) => return Err(error),
        };
    }
    let mut sections = count + extra.len();
    for change in changes {
        let Some(address) = crate::addr::parse(&change.address) else {
            return failed(format!(
                "invalid written address in emulator report: {}",
                change.address
            ));
        };
        for (index, byte) in change.bytes.iter().enumerate() {
            let Some(at) = address.checked_add(index as u64) else {
                break;
            };
            let Some((start, _, offset)) = placed
                .iter()
                .find(|(start, size, _)| at >= *start && at - *start < *size)
            else {
                continue;
            };
            if let Some(destination) = output.get_mut(*offset + (at - *start) as usize) {
                *destination = *byte;
            }
        }
    }
    let width = if wide { 8 } else { 4 };
    let directory = optional + if wide { 112 } else { 96 };
    let described = match field(directory - 4, 4) {
        Ok(count) => count >= 2,
        Err(error) => return Err(error),
    };
    let mut resolved = resolved_imports(&output, &placed, exports, width);
    // The table needs a section header of its own.
    if described && !resolved.is_empty() && (table_end + SECTION_HEADER) as u64 <= headers_size {
        // The imports of the code that did the unpacking come first, as
        // the input lists them.
        let mut imports = match field(directory + 8, 4) {
            Ok(rva) => original_imports(&output, &placed, base, rva, width),
            Err(error) => return Err(error),
        };
        imports.append(&mut resolved);
        let resolved = imports;
        let rva = image_end;
        let data = import_section(&resolved, base, rva, width);
        let (offset, raw_size) = match (
            align(output.len() as u64, file_alignment),
            align(data.bytes.len() as u64, file_alignment),
        ) {
            (Ok(offset), Ok(raw_size)) => (offset, raw_size),
            (Err(error), _) | (_, Err(error)) => return Err(error),
        };
        // Each slot holds what the file of a loaded program holds there:
        // where the name of its function is.
        for (run, names) in resolved.iter().zip(&data.names) {
            for (index, name) in names.iter().enumerate() {
                let slot = run.offset + index * width;
                if let Err(error) = put(&mut output, slot, *name, width) {
                    return Err(error);
                }
            }
        }
        output.resize((offset + raw_size) as usize, 0);
        output[offset as usize..offset as usize + data.bytes.len()].copy_from_slice(&data.bytes);
        let header = table_end;
        output[header..header + SECTION_HEADER].fill(0);
        output[header..header + 6].copy_from_slice(b".idata");
        let written = [
            put(&mut output, header + 8, data.bytes.len() as u64, 4),
            put(&mut output, header + 12, rva, 4),
            put(&mut output, header + 16, raw_size, 4),
            put(&mut output, header + 20, offset, 4),
            // Initialized data that is read.
            put(&mut output, header + 36, 0x4000_0040, 4),
            put(&mut output, directory + 8, rva, 4),
            put(&mut output, directory + 12, data.descriptors as u64, 4),
        ];
        if let Some(Err(error)) = written.into_iter().find(Result::is_err) {
            return Err(error);
        }
        sections += 1;
        image_end = match align(rva + data.bytes.len() as u64, section_alignment) {
            Ok(end) => end,
            Err(error) => return Err(error),
        };
    }
    if u32::try_from(image_end).is_err() {
        return failed("PE image size overflows");
    }
    let written = [
        put(&mut output, pe + 6, sections as u64, 2),
        put(&mut output, optional + 16, entry, 4),
        put(&mut output, optional + 56, image_end, 4),
        // The checksum no longer holds.
        put(&mut output, optional + 64, 0, 4),
    ];
    if let Some(Err(error)) = written.into_iter().find(Result::is_err) {
        return Err(error);
    }
    Ok(output)
}

/// Consecutive words of memory that hold addresses of functions of one
/// library.
struct Run {
    /// Where the first word is in memory.
    address: u64,
    /// Where it is in the output.
    offset: usize,
    dll: String,
    functions: Vec<Function>,
}

/// An import by name, or by its number among the exports of its library.
enum Function {
    Name(String),
    Ordinal(u16),
}

/// The runs of resolved imports in the sections placed in `output`.
fn resolved_imports(
    output: &[u8],
    placed: &[(u64, u64, usize)],
    exports: &BTreeMap<u64, String>,
    width: usize,
) -> Vec<Run> {
    let mut runs: Vec<Run> = Vec::new();
    if exports.is_empty() {
        return runs;
    }
    for &(start, size, offset) in placed {
        let Some(bytes) = output.get(offset..offset.saturating_add(size as usize)) else {
            continue;
        };
        for (index, slot) in bytes.chunks_exact(width).enumerate() {
            let mut value = [0u8; 8];
            value[..width].copy_from_slice(slot);
            let Some((dll, function)) = exports
                .get(&u64::from_le_bytes(value))
                .and_then(|name| name.split_once('!'))
            else {
                continue;
            };
            let address = start + (index * width) as u64;
            match runs.last_mut() {
                Some(run)
                    if run.dll == dll
                        && run.address + (run.functions.len() * width) as u64 == address =>
                {
                    run.functions.push(Function::Name(function.to_owned()));
                }
                _ => runs.push(Run {
                    address,
                    offset: offset + index * width,
                    dll: dll.to_owned(),
                    functions: vec![Function::Name(function.to_owned())],
                }),
            }
        }
    }
    runs
}

/// The bytes of the output from the address `rva` is loaded at to the end
/// of its section.
fn loaded<'a>(
    output: &'a [u8],
    placed: &[(u64, u64, usize)],
    base: u64,
    rva: u64,
) -> Option<(&'a [u8], usize)> {
    let Some(address) = base.checked_add(rva) else {
        return None;
    };
    let Some((start, size, offset)) = placed
        .iter()
        .find(|(start, size, _)| address >= *start && address - *start < *size)
    else {
        return None;
    };
    let from = offset + (address - start) as usize;
    output
        .get(from..offset + *size as usize)
        .map(|bytes| (bytes, from))
}

/// The imports the input's directory at `rva` lists, read from the
/// output: those of the code that did the unpacking.
fn original_imports(
    output: &[u8],
    placed: &[(u64, u64, usize)],
    base: u64,
    rva: u64,
    width: usize,
) -> Vec<Run> {
    let mut runs = Vec::new();
    if rva == 0 {
        return runs;
    }
    let Some((descriptors, _)) = loaded(output, placed, base, rva) else {
        return runs;
    };
    let text = |rva: u64| {
        let Some((bytes, _)) = loaded(output, placed, base, rva) else {
            return None;
        };
        let Some(end) = bytes.iter().position(|byte| *byte == 0) else {
            return None;
        };
        std::str::from_utf8(&bytes[..end]).ok().map(str::to_owned)
    };
    for descriptor in descriptors.as_chunks::<20>().0.iter().take(256) {
        if descriptor.iter().all(|byte| *byte == 0) {
            break;
        }
        let part = |at: usize| {
            u64::from(u32::from_le_bytes(
                descriptor[at..at + 4].try_into().expect("four bytes"),
            ))
        };
        let (lookup, name, first) = (part(0), part(12), part(16));
        let (Some(dll), Some((thunks, _)), Some((_, offset))) = (
            text(name),
            loaded(
                output,
                placed,
                base,
                if lookup == 0 { first } else { lookup },
            ),
            loaded(output, placed, base, first),
        ) else {
            continue;
        };
        let mut functions = Vec::new();
        for thunk in thunks.chunks_exact(width).take(4096) {
            let mut value = [0u8; 8];
            value[..width].copy_from_slice(thunk);
            let value = u64::from_le_bytes(value);
            if value == 0 {
                break;
            }
            if value >> (width * 8 - 1) != 0 {
                functions.push(Function::Ordinal(value as u16));
            } else if let Some(function) = text(value + 2) {
                functions.push(Function::Name(function));
            } else {
                break;
            }
        }
        if functions.is_empty() {
            continue;
        }
        runs.push(Run {
            address: base + first,
            offset,
            dll,
            functions,
        });
    }
    runs
}

struct ImportSection {
    bytes: Vec<u8>,
    /// The bytes of the descriptors at its start.
    descriptors: usize,
    /// For each run, where the name of each function is, from the base.
    names: Vec<Vec<u64>>,
}

/// An import section at `rva`: a descriptor for each run, the end of the
/// list, then for each run its lookup table, the names of its functions
/// and the name of its library. Everything a descriptor names is in the
/// section, as readers of import tables expect.
fn import_section(runs: &[Run], base: u64, rva: u64, width: usize) -> ImportSection {
    let descriptors = (runs.len() + 1) * 20;
    let mut bytes = vec![0u8; descriptors];
    let mut names = Vec::new();
    for (index, run) in runs.iter().enumerate() {
        let lookup = bytes.len();
        bytes.resize(lookup + (run.functions.len() + 1) * width, 0);
        let mut run_names = Vec::new();
        for (position, function) in run.functions.iter().enumerate() {
            let name = match function {
                Function::Ordinal(ordinal) => (1u64 << (width * 8 - 1)) | u64::from(*ordinal),
                Function::Name(function) => {
                    let name = rva + bytes.len() as u64;
                    // A hint of zero, the name and its end, to an even length.
                    bytes.extend_from_slice(&[0, 0]);
                    bytes.extend_from_slice(function.as_bytes());
                    bytes.push(0);
                    if !bytes.len().is_multiple_of(2) {
                        bytes.push(0);
                    }
                    name
                }
            };
            run_names.push(name);
            bytes[lookup + position * width..lookup + (position + 1) * width]
                .copy_from_slice(&name.to_le_bytes()[..width]);
        }
        let library = rva + bytes.len() as u64;
        bytes.extend_from_slice(run.dll.as_bytes());
        bytes.push(0);
        bytes.resize(bytes.len().next_multiple_of(width), 0);
        let descriptor = index * 20;
        let fields = [
            (0, rva + lookup as u64),
            (12, library),
            (16, run.address - base),
        ];
        for (offset, value) in fields {
            bytes[descriptor + offset..descriptor + offset + 4]
                .copy_from_slice(&value.to_le_bytes()[..4]);
        }
        names.push(run_names);
    }
    ImportSection {
        bytes,
        descriptors,
        names,
    }
}

#[cfg(test)]
mod tests {
    use object::{Object as _, ObjectSection as _};

    use super::*;

    fn fixture(name: &str) -> Image {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        crate::loader::load(&path).expect("a PE fixture")
    }

    fn change(address: u64, bytes: &[u8]) -> crate::emulation::MemoryChange {
        crate::emulation::MemoryChange {
            address: crate::addr::format(address),
            bytes: bytes.to_vec(),
            hex: String::new(),
        }
    }

    fn imports(file: &object::File<'_>) -> Vec<(String, String)> {
        file.imports()
            .expect("the imports")
            .map(|import| {
                let import = import.expect("an import");
                let name = match import.name() {
                    object::NameOrOrdinal::Name(name) => String::from_utf8_lossy(name).into_owned(),
                    object::NameOrOrdinal::Ordinal(ordinal) => format!("#{ordinal}"),
                };
                (String::from_utf8_lossy(import.library()).into_owned(), name)
            })
            .collect()
    }

    #[test]
    fn memory_replaces_section_bytes_and_the_entry_moves() {
        let image = fixture("pe64.exe");
        let base = 0x1_4000_0000u64;
        let rebuilt = rebuild(
            &image,
            &[change(base + 0x1010, &[0xb8, 42, 0, 0, 0, 0xc3])],
            base + 0x1010,
            &[],
            &BTreeMap::new(),
            1 << 20,
        )
        .expect("a rebuilt image");
        let file = object::File::parse(rebuilt.as_slice()).expect("a PE file");
        assert_eq!(file.entry(), base + 0x1010);
        let text = file.section_by_name(".text").expect("the code section");
        let bytes = text.data().expect("its bytes");
        assert_eq!(&bytes[0x10..0x16], [0xb8, 42, 0, 0, 0, 0xc3]);
        // Bytes nothing wrote are the input's.
        let original = image.read_vaddr(base + 0x1000, 0x10).expect("input bytes");
        assert_eq!(&bytes[..0x10], original);
        // With nothing resolved, no section is added.
        assert_eq!(file.sections().count(), image.sections.len());
    }

    #[test]
    fn resolved_addresses_become_an_import_table() {
        for (name, base, slots, width) in [
            ("pe64.exe", 0x1_4000_0000u64, 0x20e0u64, 8usize),
            ("crt_windows.i686.exe", 0x40_0000, 0x3100, 4),
        ] {
            let image = fixture(name);
            let exports: BTreeMap<u64, String> = [
                (0x3003_8000, "user32.dll!MessageBoxA"),
                (0x3003_8010, "user32.dll!GetDesktopWindow"),
                (0x3004_8000, "kernel32.dll!GetTickCount"),
            ]
            .into_iter()
            .map(|(address, name)| (address, name.to_owned()))
            .collect();
            // Two functions of one library side by side, then one of
            // another with no word between.
            let mut written = Vec::new();
            for address in [0x3003_8000u64, 0x3003_8010, 0x3004_8000] {
                written.extend_from_slice(&address.to_le_bytes()[..width]);
            }
            let rebuilt = rebuild(
                &image,
                &[change(base + slots, &written)],
                base + 0x1000,
                &[],
                &exports,
                1 << 20,
            )
            .expect("a rebuilt image");
            let file = object::File::parse(rebuilt.as_slice()).expect("a PE file");
            let found = imports(&file);
            let resolved: Vec<(&str, &str)> = found
                .iter()
                .rev()
                .take(3)
                .rev()
                .map(|(library, name)| (library.as_str(), name.as_str()))
                .collect();
            assert_eq!(
                resolved,
                [
                    ("user32.dll", "MessageBoxA"),
                    ("user32.dll", "GetDesktopWindow"),
                    ("kernel32.dll", "GetTickCount"),
                ],
                "{name}"
            );
            // The imports the input lists are kept, before them.
            let kept = image.qualified_imports.len();
            assert_eq!(found.len(), kept + 3, "{name}: {found:?}");
            let table = file.section_by_name(".idata").expect("the import section");
            assert!(table.address() > base + slots, "{name}");
            // The loader of this crate names the slots as well.
            let directory =
                std::env::temp_dir().join(format!("velk-pe-rebuild-{}-{name}", std::process::id()));
            std::fs::write(&directory, &rebuilt).expect("writing the rebuilt image");
            let reloaded = crate::loader::load(&directory);
            std::fs::remove_file(&directory).expect("removing the rebuilt image");
            let reloaded = reloaded.expect("loading the rebuilt image");
            assert_eq!(
                reloaded
                    .qualified_imports
                    .get(&(base + slots + 2 * width as u64))
                    .map(String::as_str),
                Some("kernel32.dll!GetTickCount"),
                "{name}"
            );
        }
    }

    #[test]
    fn an_entry_or_a_region_the_image_cannot_address_is_refused() {
        let image = fixture("pe64.exe");
        let base = 0x1_4000_0000u64;
        let none = BTreeMap::new();
        let below = rebuild(&image, &[], base - 0x1000, &[], &none, 1 << 20);
        assert!(below.is_err());
        let region = Section {
            vaddr: 0x3000_0000,
            size: 0x1000,
            ..image.sections[0].clone()
        };
        let outside = rebuild(&image, &[], base + 0x1000, &[region], &none, 1 << 20);
        assert!(
            outside
                .err()
                .is_some_and(|error| error.to_string().contains("outside what the PE image")),
        );
        // A limit below the size of the sections stops the rebuild.
        assert!(rebuild(&image, &[], base + 0x1000, &[], &none, 0x100).is_err());
    }
}
