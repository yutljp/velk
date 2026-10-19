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
