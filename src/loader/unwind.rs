//! Function extents from the unwind tables. Every function a compiler emits
//! with unwind information has a frame description covering it exactly; the
//! state the description starts in tells a function entry, where only the
//! return address is saved, from a fragment split off a function, such as
//! its cold part, which starts inside the parent's frame.

use gimli::{
    BaseAddresses, CfaRule, CieOrFde, EhFrame, LittleEndian, Register, UnwindContext, UnwindSection,
};

use crate::loader::{Image, Isa};

/// One frame description: the code it covers and whether that code starts
/// a function, or continues one inside its frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Frame {
    pub start: u64,
    pub size: u64,
    pub kind: FrameKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameKind {
    /// Only the return address is saved: a function starts here.
    Entry,
    /// The frame is already set up: code split off a function.
    Fragment,
    /// A frame address computed by an expression, as for linkage stubs.
    Other,
}

pub(crate) fn frames(image: &Image) -> Vec<Frame> {
    let Some(section) = image
        .sections
        .iter()
        .find(|section| matches!(section.name.as_str(), ".eh_frame" | "__eh_frame"))
    else {
        return Vec::new();
    };
    let Some(data) = image.section_data(&section.name) else {
        return Vec::new();
    };
    // The stack pointer, and the column holding the return address.
    let (stack, return_address) = match image.isa {
        Isa::X86_64 => (Register(7), Register(16)),
        Isa::AArch64 => (Register(31), Register(30)),
        Isa::Unsupported => return Vec::new(),
    };
    let mut eh_frame = EhFrame::new(data, LittleEndian);
    eh_frame.set_address_size(8);
    let bases = BaseAddresses::default().set_eh_frame(section.vaddr);
    let mut context = Box::new(UnwindContext::new());
    let mut frames = Vec::new();
    let mut entries = eh_frame.entries(&bases);
    while let Ok(Some(entry)) = entries.next() {
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let Ok(fde) = partial.parse(EhFrame::cie_from_offset) else {
            continue;
        };
        if fde.len() == 0 {
            continue;
        }
        let kind = match fde.rows(&eh_frame, &bases, &mut context) {
            Ok(mut rows) => match rows.next_row() {
                Ok(Some(row)) => {
                    // The call pushed the return address on x86-64.
                    let entry_offset = if image.isa == Isa::X86_64 { 8 } else { 0 };
                    match row.cfa() {
                        CfaRule::RegisterAndOffset { register, offset }
                            if *register == stack
                                && *offset == entry_offset
                                && row.registers().all(|(register, _)| {
                                    *register == return_address || register.0 > 32
                                }) =>
                        {
                            FrameKind::Entry
                        }
                        CfaRule::RegisterAndOffset { .. } => FrameKind::Fragment,
                        CfaRule::Expression(_) => FrameKind::Other,
                    }
                }
                _ => FrameKind::Other,
            },
            Err(_) => FrameKind::Other,
        };
        frames.push(Frame {
            start: fde.initial_address(),
            size: fde.len(),
            kind,
        });
    }
    frames.sort_by_key(|frame| frame.start);
    frames.dedup_by_key(|frame| frame.start);
    frames
}

/// The landing pads the exception tables name, each with the code ranges
/// whose calls unwind into it.
pub(crate) fn landing_pads(image: &Image) -> std::collections::BTreeMap<u64, Vec<(u64, u64)>> {
    let mut pads: std::collections::BTreeMap<u64, Vec<(u64, u64)>> = Default::default();
    let Some(section) = image
        .sections
        .iter()
        .find(|section| matches!(section.name.as_str(), ".eh_frame" | "__eh_frame"))
    else {
        return pads;
    };
    let Some(data) = image.section_data(&section.name) else {
        return pads;
    };
    let mut eh_frame = EhFrame::new(data, LittleEndian);
    eh_frame.set_address_size(8);
    let bases = BaseAddresses::default().set_eh_frame(section.vaddr);
    let mut entries = eh_frame.entries(&bases);
    while let Ok(Some(entry)) = entries.next() {
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let Ok(fde) = partial.parse(EhFrame::cie_from_offset) else {
            continue;
        };
        let Some(gimli::Pointer::Direct(lsda)) = fde.lsda() else {
            continue;
        };
        let _ = call_sites(image, lsda, fde.initial_address(), &mut pads);
    }
    pads
}

/// Reads the call-site table of the exception table at `lsda`, for the
/// function starting at `function`.
fn call_sites(
    image: &Image,
    lsda: u64,
    function: u64,
    pads: &mut std::collections::BTreeMap<u64, Vec<(u64, u64)>>,
) -> Option<()> {
    let mut at = lsda;
    let byte = |at: &mut u64| -> Option<u8> {
        let value = image.read_vaddr(*at, 1)?[0];
        *at += 1;
        Some(value)
    };
    let uleb = |at: &mut u64| -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let next = byte(at)?;
            value |= u64::from(next & 0x7f) << shift;
            if next & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    };
    // A value in the given pointer encoding; only the forms these tables
    // use for offsets.
    let encoded = |at: &mut u64, encoding: u8| -> Option<u64> {
        let place = *at;
        let fixed = |at: &mut u64, size: u64| -> Option<u64> {
            let bytes = image.read_vaddr(*at, size)?;
            *at += size;
            let mut buffer = [0u8; 8];
            buffer[..size as usize].copy_from_slice(&bytes[..size as usize]);
            Some(u64::from_le_bytes(buffer))
        };
        let value = match encoding & 0x0f {
            0x00 => fixed(at, 8)?,
            0x01 => uleb(at)?,
            0x02 => fixed(at, 2)?,
            0x03 => fixed(at, 4)?,
            0x04 | 0x0c => fixed(at, 8)?,
            0x0a => fixed(at, 2)? as i16 as i64 as u64,
            0x0b => fixed(at, 4)? as i32 as i64 as u64,
            _ => return None,
        };
        Some(match encoding & 0x70 {
            0x00 => value,
            0x10 => place.wrapping_add(value),
            _ => return None,
        })
    };
    let start_encoding = byte(&mut at)?;
    let base = if start_encoding == 0xff {
        function
    } else {
        encoded(&mut at, start_encoding)?
    };
    if byte(&mut at)? != 0xff {
        uleb(&mut at)?;
    }
    let site_encoding = byte(&mut at)?;
    let length = uleb(&mut at)?;
    let end = at + length;
    while at < end {
        let start = encoded(&mut at, site_encoding)?;
        let size = encoded(&mut at, site_encoding)?;
        let pad = encoded(&mut at, site_encoding)?;
        uleb(&mut at)?;
        if pad != 0 {
            pads.entry(base + pad)
                .or_default()
                .push((base + start, base + start + size));
        }
    }
    Some(())
}

#[cfg(test)]
mod probe {
    #[test]
    #[ignore]
    fn dump_frames() {
        let path = std::env::var("VELK_FIXTURE").expect("set VELK_FIXTURE");
        let image = crate::loader::load(std::path::Path::new(&path)).expect("loads");
        for frame in super::frames(&image) {
            println!("0x{:x} {} {:?}", frame.start, frame.size, frame.kind);
        }
    }
}
