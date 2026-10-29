//! Explicit mapping of headerless code into the analysis address space.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{ArmMode, Format, Image, Isa, NameSource, bytes, discover, upsert};
use crate::error::{Error, Result};

/// Selection options for a normal file or a headerless image.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenOptions {
    /// Architecture selection for a normal file.
    pub arch: Option<super::Architecture>,
    /// Explicit description of headerless bytes.
    pub raw: Option<RawOptions>,
    /// Emulation bounds and stop address for ELF unpacking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unpack: Option<crate::unpack::Options>,
    /// Persistent cache path or false to disable it; omission uses `VELK_CACHE`.
    #[serde(default)]
    pub cache: Option<crate::service::CacheLocation>,
}

/// The instruction set of headerless code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum)]
pub enum RawArchitecture {
    /// 64-bit x86, using the System V calling convention.
    #[serde(rename = "x86_64")]
    #[value(name = "x86_64", alias = "x86-64")]
    X86_64,
    /// 32-bit x86, using cdecl.
    #[serde(rename = "i386")]
    #[value(name = "i386", alias = "x86-32")]
    I386,
    /// `AArch64`, using AAPCS64.
    #[serde(rename = "aarch64")]
    Aarch64,
    /// A32 instructions, using AAPCS32.
    #[serde(rename = "arm32")]
    Arm32,
    /// T32 instructions, using AAPCS32.
    #[serde(rename = "thumb")]
    Thumb,
}

/// Byte order requested for a raw image.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum ByteOrder {
    /// Least significant byte first.
    #[default]
    Little,
    /// Most significant byte first; currently rejected by the code loader.
    Big,
}

/// Mapping and entry points for a headerless image.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawOptions {
    /// Instruction set and default ARM mode.
    pub arch: RawArchitecture,
    /// Address of the first input byte. Use a string for full 64-bit precision.
    #[serde(
        serialize_with = "crate::addr::serialize",
        deserialize_with = "deserialize_address"
    )]
    pub base: u64,
    /// Entry addresses; an empty list selects the base. Odd ARM addresses select Thumb.
    #[serde(
        default,
        serialize_with = "serialize_entries",
        deserialize_with = "deserialize_entries"
    )]
    pub entries: Vec<u64>,
    /// Data and instruction byte order; defaults to little endian.
    #[serde(default)]
    pub byte_order: ByteOrder,
}

fn serialize_entries<S: serde::Serializer>(
    entries: &[u64],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    let entries: Vec<String> = entries
        .iter()
        .map(|entry| crate::addr::format(*entry))
        .collect();
    entries.serialize(serializer)
}

fn deserialize_address<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u64, D::Error> {
    let word = match crate::emulation::Word::deserialize(deserializer) {
        Ok(word) => word,
        Err(error) => return Err(error),
    };
    word.value().map_err(serde::de::Error::custom)
}

fn deserialize_entries<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<u64>, D::Error> {
    let words = match Vec::<crate::emulation::Word>::deserialize(deserializer) {
        Ok(words) => words,
        Err(error) => return Err(error),
    };
    words
        .into_iter()
        .map(|word| word.value().map_err(serde::de::Error::custom))
        .collect()
}

pub(super) fn load_raw(
    path: &Path,
    options: &RawOptions,
    saved: impl FnOnce(&Image) -> Option<crate::service::cache::Saved>,
) -> Result<Image> {
    if options.byte_order != ByteOrder::Little {
        return Err(Error::Raw("big-endian code is not supported".to_owned()));
    }
    let bytes = match bytes::Bytes::read(path) {
        Ok(bytes) => bytes,
        Err(error) => return Err(error),
    };
    if bytes.is_empty() {
        return Err(Error::Raw("the file is empty".to_owned()));
    }
    if object::FileKind::parse(bytes.as_slice()).is_ok() {
        return Err(Error::Raw(
            "the file has a recognized header; open it without raw options".to_owned(),
        ));
    }
    let isa = match options.arch {
        RawArchitecture::X86_64 => Isa::X86_64,
        RawArchitecture::I386 => Isa::I386,
        RawArchitecture::Aarch64 => Isa::AArch64,
        RawArchitecture::Arm32 | RawArchitecture::Thumb => Isa::Arm32,
    };
    let Some(end) = options.base.checked_add(bytes.len() as u64) else {
        return Err(Error::Raw(
            "load address plus file size overflows".to_owned(),
        ));
    };
    if matches!(isa, Isa::I386 | Isa::Arm32) && end > 1 << 32 {
        return Err(Error::Raw(
            "image exceeds the 32-bit address space".to_owned(),
        ));
    }
    let alignment = match options.arch {
        RawArchitecture::Aarch64 | RawArchitecture::Arm32 => 4,
        RawArchitecture::Thumb => 2,
        _ => 1,
    };
    if !options.base.is_multiple_of(alignment) {
        return Err(Error::Raw(format!(
            "load address must be aligned to {alignment} bytes"
        )));
    }
    let mut image = Image::code_image(isa, options.base, bytes);
    image.format = Format::Raw;
    image.stripped = true;
    image.sections[0].name = "raw".to_owned();
    if isa == Isa::Arm32 {
        image.arm_modes.insert(
            options.base,
            if options.arch == RawArchitecture::Thumb {
                ArmMode::Thumb
            } else {
                ArmMode::Arm
            },
        );
    }
    let entries = if options.entries.is_empty() {
        &[options.base][..]
    } else {
        &options.entries
    };
    let mut entry_modes = std::collections::BTreeMap::new();
    for &entry in entries {
        let address = image.code_address(entry);
        let thumb = isa == Isa::Arm32 && (entry & 1 != 0 || options.arch == RawArchitecture::Thumb);
        let alignment = if thumb { 2 } else { alignment };
        if !(options.base..end).contains(&address) || !address.is_multiple_of(alignment) {
            return Err(Error::Raw(format!(
                "entry 0x{entry:x} is outside the image or misaligned"
            )));
        }
        if isa == Isa::Arm32 {
            let mode = if thumb { ArmMode::Thumb } else { ArmMode::Arm };
            if entry_modes
                .insert(address, mode)
                .is_some_and(|previous| previous != mode)
            {
                return Err(Error::Raw(format!(
                    "conflicting ARM modes at entry 0x{address:x}"
                )));
            }
            image.arm_modes.insert(address, mode);
        }
        if image.entry.is_none() {
            image.entry = Some(address);
        }
        upsert(&mut image.functions, address, None, None, NameSource::Entry);
    }
    if let Some(saved) = saved(&image) {
        saved.restore(&mut image);
        return Ok(image);
    }
    image.scan_prologues();
    discover::estimate_sizes(&image.sections, &mut image.functions);
    Ok(image)
}
