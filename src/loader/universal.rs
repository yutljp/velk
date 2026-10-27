//! Selects bounded Mach-O slices before ordinary object loading.

use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Architecture requested when opening a Mach-O file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    /// `AArch64`, including the arm64e subtype.
    Arm64,
    /// `AArch64` with pointer authentication.
    Arm64e,
    /// 64-bit x86.
    #[value(name = "x86_64")]
    #[serde(rename = "x86_64")]
    X86_64,
}

impl Architecture {
    fn matches(self, cpu: u32, subtype: u32) -> bool {
        match self {
            Self::Arm64 => object::macho::CpuType(cpu) == object::macho::CPU_TYPE_ARM64,
            Self::Arm64e => {
                object::macho::CpuType(cpu) == object::macho::CPU_TYPE_ARM64
                    && subtype & 0x00ff_ffff == 2
            }
            Self::X86_64 => object::macho::CpuType(cpu) == object::macho::CPU_TYPE_X86_64,
        }
    }

    fn host() -> Option<Self> {
        match std::env::consts::ARCH {
            "aarch64" => Some(Self::Arm64),
            "x86_64" => Some(Self::X86_64),
            _ => None,
        }
    }
}

/// An available architecture and its byte range in a universal Mach-O file.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Slice {
    /// Architecture name, preserving the arm64e subtype.
    pub arch: String,
    /// Mach-O CPU type.
    pub cpu_type: u32,
    /// Mach-O CPU subtype, including capability bits.
    pub cpu_subtype: u32,
    /// Offset in the universal file.
    pub offset: u64,
    /// Length of this slice.
    pub size: u64,
}

fn slices<F: FatArch>(arches: &[F]) -> Vec<Slice> {
    let mut slices = Vec::new();
    for arch in arches {
        let cpu = arch.cputype();
        let subtype = arch.cpusubtype().0;
        let name = match cpu {
            object::macho::CPU_TYPE_ARM64 if subtype & 0x00ff_ffff == 2 => "arm64e".to_owned(),
            object::macho::CPU_TYPE_ARM64 => "arm64".to_owned(),
            object::macho::CPU_TYPE_X86_64 => "x86_64".to_owned(),
            _ => format!("cpu-{cpu:#x}-subtype-{subtype:#x}"),
        };
        let (offset, size) = arch.file_range();
        slices.push(Slice {
            arch: name,
            cpu_type: cpu.0,
            cpu_subtype: subtype,
            offset,
            size,
        });
    }
    slices
}

pub(super) fn select(
    bytes: &[u8],
    requested: Option<Architecture>,
) -> Result<(&[u8], Vec<Slice>, u64)> {
    let available = match object::FileKind::parse(bytes) {
        Ok(object::FileKind::MachOFat32) => match MachOFatFile32::parse(bytes) {
            Ok(file) => slices(file.arches()),
            Err(error) => return Err(Error::Architecture(format!("invalid fat header: {error}"))),
        },
        Ok(object::FileKind::MachOFat64) => match MachOFatFile64::parse(bytes) {
            Ok(file) => slices(file.arches()),
            Err(error) => {
                return Err(Error::Architecture(format!(
                    "invalid fat64 header: {error}"
                )));
            }
        },
        _ => {
            if let Some(requested) = requested {
                use object::Object as _;
                let matches = match object::File::parse(bytes) {
                    Ok(file) => match requested {
                        Architecture::Arm64 => file.architecture() == object::Architecture::Aarch64,
                        Architecture::X86_64 => file.architecture() == object::Architecture::X86_64,
                        Architecture::Arm64e => {
                            matches!(&file, object::File::MachO64(macho) if requested.matches(macho.macho_header().cputype.get(macho.endian()).0, macho.macho_header().cpusubtype.get(macho.endian()).0))
                        }
                    },
                    Err(_) => return Ok((bytes, Vec::new(), 0)),
                };
                if !matches {
                    return Err(Error::Architecture(format!(
                        "requested {requested:?} does not match the input architecture"
                    )));
                }
            }
            return Ok((bytes, Vec::new(), 0));
        }
    };
    let names: Vec<&str> = available.iter().map(|slice| slice.arch.as_str()).collect();
    let error = |detail: String| {
        Error::Architecture(format!("{detail}; available slices: {}", names.join(", ")))
    };
    let Some(wanted) = requested.or_else(Architecture::host) else {
        return Err(error(
            "host architecture is unsupported; select --arch explicitly".to_owned(),
        ));
    };
    let Some(slice) = available
        .iter()
        .find(|slice| wanted.matches(slice.cpu_type, slice.cpu_subtype))
    else {
        return Err(error(format!("no slice matching {wanted:?}")));
    };
    let range = usize::try_from(slice.offset)
        .ok()
        .zip(usize::try_from(slice.size).ok());
    let slice_bytes = range.and_then(|(offset, size)| {
        offset
            .checked_add(size)
            .and_then(|end| bytes.get(offset..end))
    });
    let Some(slice_bytes) = slice_bytes else {
        return Err(error(format!(
            "{} slice at {:#x} with size {:#x} is outside the file",
            slice.arch, slice.offset, slice.size
        )));
    };
    let header = match object::File::parse(slice_bytes) {
        Ok(object::File::MachO64(file)) => {
            let header = file.macho_header();
            (
                header.cputype.get(file.endian()).0,
                header.cpusubtype.get(file.endian()).0,
            )
        }
        Ok(object::File::MachO32(file)) => {
            let header = file.macho_header();
            (
                header.cputype.get(file.endian()).0,
                header.cpusubtype.get(file.endian()).0,
            )
        }
        Ok(_) => return Err(error("slice is not Mach-O".to_owned())),
        Err(cause) => return Err(error(format!("invalid {} slice: {cause}", slice.arch))),
    };
    if header != (slice.cpu_type, slice.cpu_subtype) {
        return Err(error(
            "slice header disagrees with its architecture table".to_owned(),
        ));
    }
    let offset = slice.offset;
    Ok((slice_bytes, available, offset))
}
