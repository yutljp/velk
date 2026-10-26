//! Function extents from the unwind tables. Every function a compiler emits
//! with unwind information has a frame description covering it exactly; the
//! state the description starts in tells a function entry, where only the
//! return address is saved, from a fragment split off a function, such as
//! its cold part, which starts inside the parent's frame.

mod lsda;
mod macho;
mod pe;
pub(crate) use lsda::Region;

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

pub(super) struct Architecture {
    pub(super) stack: Register,
    return_address: Register,
    pub(super) entry_offset: i64,
}

pub(super) fn architecture(isa: Isa) -> Option<Architecture> {
    let (stack, return_address, entry_offset) = match isa {
        Isa::I386 => (Register(4), Register(8), 4),
        Isa::X86_64 => (Register(7), Register(16), 8),
        Isa::AArch64 => (Register(31), Register(30), 0),
        Isa::Arm32 | Isa::Unsupported => return None,
    };
    Some(Architecture {
        stack,
        return_address,
        entry_offset,
    })
}

fn inputs(image: &Image) -> Option<(EhFrame<gimli::EndianSlice<'_, LittleEndian>>, BaseAddresses)> {
    let Some(section) = image
        .sections
        .iter()
        .find(|section| matches!(section.name.as_str(), ".eh_frame" | "__eh_frame"))
    else {
        return None;
    };
    let Some(data) = image.section_data(&section.name) else {
        return None;
    };
    let mut eh_frame = EhFrame::new(data, LittleEndian);
    eh_frame.set_address_size(crate::arch::pointer_bytes(image.isa));
    let bases = BaseAddresses::default().set_eh_frame(section.vaddr);
    Some((eh_frame, bases))
}

pub(crate) fn frames(image: &Image) -> Vec<Frame> {
    if image.format == crate::loader::Format::Pe {
        return pe::frames(image);
    }
    let Some((eh_frame, bases)) = inputs(image) else {
        return Vec::new();
    };
    let Some(Architecture {
        stack,
        return_address,
        entry_offset,
    }) = architecture(image.isa)
    else {
        return Vec::new();
    };
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
                Ok(Some(row)) => match row.cfa() {
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
                },
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

/// A stretch of code over which the unwind table holds the stack at one
/// height relative to the function's entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StackRow {
    pub start: u64,
    pub end: u64,
    /// The stack pointer is where it was on entry: only the return address
    /// is on the stack, as at the first instruction.
    pub at_entry: bool,
    pub cfa: (Register, i64),
}

/// Every row of every frame description, by address. A frame address kept
/// in another register than the stack pointer means a frame is set up.
pub(crate) fn stack_rows(image: &Image) -> Vec<StackRow> {
    let Some((eh_frame, bases)) = inputs(image) else {
        return Vec::new();
    };
    let Some(Architecture {
        stack,
        entry_offset,
        ..
    }) = architecture(image.isa)
    else {
        return Vec::new();
    };
    let mut context = Box::new(UnwindContext::new());
    let mut out = Vec::new();
    let mut entries = eh_frame.entries(&bases);
    while let Ok(Some(entry)) = entries.next() {
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let Ok(fde) = partial.parse(EhFrame::cie_from_offset) else {
            continue;
        };
        let Ok(mut rows) = fde.rows(&eh_frame, &bases, &mut context) else {
            continue;
        };
        while let Ok(Some(row)) = rows.next_row() {
            let at_entry = match row.cfa() {
                CfaRule::RegisterAndOffset { register, offset } => {
                    *register == stack && *offset == entry_offset
                }
                CfaRule::Expression(_) => continue,
            };
            out.push(StackRow {
                start: row.start_address(),
                end: row.end_address(),
                at_entry,
                cfa: match row.cfa() {
                    CfaRule::RegisterAndOffset { register, offset } => (*register, *offset),
                    CfaRule::Expression(_) => continue,
                },
            });
        }
    }
    out.sort_by_key(|row| row.start);
    out
}

/// The landing pads the exception tables name, each with the code ranges
/// whose calls unwind into it.
pub(crate) fn exception_regions(image: &Image) -> Vec<Region> {
    let mut regions = macho::regions(image);
    let Some((eh_frame, bases)) = inputs(image) else {
        return regions;
    };
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
        regions.extend(lsda::read(image, lsda, fde.initial_address()));
    }
    regions.sort_by_key(|region| {
        (
            region.function,
            region.start,
            region.end,
            region.landing_pad,
        )
    });
    regions.dedup_by_key(|region| {
        (
            region.function,
            region.start,
            region.end,
            region.landing_pad,
        )
    });
    regions
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

#[cfg(test)]
mod tests {
    #[test]
    fn the_table_has_the_stack_as_on_entry_only_outside_the_frame() {
        use crate::loader::Isa;
        use gimli::Register;

        for (isa, expected) in [
            (Isa::I386, (4, 8, 4)),
            (Isa::X86_64, (7, 16, 8)),
            (Isa::AArch64, (31, 30, 0)),
        ] {
            let facts = super::architecture(isa).expect("supported unwind architecture");
            assert_eq!(
                (facts.stack, facts.return_address, facts.entry_offset),
                (Register(expected.0), Register(expected.1), expected.2)
            );
        }
        for isa in [Isa::Arm32, Isa::Unsupported] {
            assert!(super::architecture(isa).is_none());
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cold_gcc");
        let image = crate::loader::load(&path).expect("loads");
        // lookup: pushes three registers and reserves 0x50 bytes, and pops
        // them all before its return at 0x12fc.
        assert_eq!(image.stack_at_entry(0x1290), Some(true));
        assert_eq!(image.stack_at_entry(0x12dd), Some(false));
        assert_eq!(image.stack_at_entry(0x12fa), Some(false));
        assert_eq!(image.stack_at_entry(0x12fc), Some(true));
        assert_eq!(image.stack_at_entry(0), None);
    }
}
