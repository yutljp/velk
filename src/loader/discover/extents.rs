//! Estimated extents must include code reached across another call entry.

use std::collections::HashSet;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic};

use crate::loader::{Image, Isa, NameSource};

pub(in crate::loader) fn refine(image: &mut Image) {
    if !matches!(image.isa, Isa::X86_64 | Isa::I386) {
        return;
    }
    let mut sizes = Vec::new();
    for function in image.functions.values() {
        if !function.size_estimated {
            continue;
        }
        let Some(section) = image.section_at(function.addr) else {
            continue;
        };
        let section_end = section.vaddr.saturating_add(section.file_size);
        let mut limit = section_end;
        for next in image.functions.range(function.addr.saturating_add(1)..) {
            if !next.1.sources.contains(&NameSource::Call) {
                limit = limit.min(*next.0);
                break;
            }
        }
        limit = limit.max(function.addr.saturating_add(function.size.unwrap_or(0)));
        if function.sources.contains(&NameSource::Call) {
            for (_, enclosing) in image.functions.range(..function.addr).rev() {
                if enclosing.size_estimated {
                    continue;
                }
                let end = enclosing.addr.saturating_add(enclosing.size.unwrap_or(0));
                if function.addr < end {
                    limit = limit.min(end);
                    break;
                }
            }
        }
        if let Some((&start, _)) = image
            .fragments
            .range(function.addr.saturating_add(1)..)
            .next()
        {
            limit = limit.min(start);
        }
        limit = limit.min(section_end);
        if limit <= function.addr {
            continue;
        }
        let reached = reachable_end(image, function.addr, limit);
        let mut end = limit;
        for (&start, _) in image
            .functions
            .range(function.addr.saturating_add(1)..limit)
        {
            if start >= reached {
                end = start;
                break;
            }
        }
        sizes.push((function.addr, end - function.addr));
    }
    for (address, size) in sizes {
        image
            .functions
            .get_mut(&address)
            .expect("function exists")
            .size = Some(size);
    }
}

fn reachable_end(image: &Image, start: u64, limit: u64) -> u64 {
    let bitness = if image.isa == Isa::I386 { 32 } else { 64 };
    let mut pending = vec![start];
    let mut seen = HashSet::new();
    let mut end = start;
    while let Some(mut address) = pending.pop() {
        while (start..limit).contains(&address) && seen.insert(address) {
            let Some(bytes) = image.read_vaddr(address, (limit - address).min(15)) else {
                return limit;
            };
            let mut decoder = Decoder::with_ip(bitness, bytes, address, DecoderOptions::NONE);
            let Some(instruction) = super::decode(&mut decoder) else {
                return limit;
            };
            end = end.max(instruction.next_ip());
            if matches!(
                instruction.mnemonic(),
                Mnemonic::Int3 | Mnemonic::Ud2 | Mnemonic::Hlt
            ) {
                break;
            }
            let target = super::branch_target(image, &instruction);
            match instruction.flow_control() {
                FlowControl::ConditionalBranch => pending.push(target),
                FlowControl::UnconditionalBranch => {
                    pending.push(target);
                    break;
                }
                // An unresolved dispatch can reach cases beyond any candidate boundary.
                FlowControl::IndirectBranch => return limit,
                _ if super::ends_path(&instruction) => break,
                _ => {}
            }
            address = instruction.next_ip();
        }
    }
    end
}

#[cfg(test)]
mod tests {
    #[test]
    fn terminators_keep_adjacent_call_entries_separate() {
        use crate::loader::{Image, Isa, NameSource};

        for terminal in [0xc3, 0xf4, 0xcc] {
            let mut image = Image::from_code(
                Isa::X86_64,
                0,
                vec![0xb8, 7, 0, 0, 0, terminal, 0xb8, 9, 0, 0, 0, 0xc3],
            );
            super::super::super::upsert(&mut image.functions, 0, None, Some(12), NameSource::Call);
            super::super::super::upsert(&mut image.functions, 6, None, Some(6), NameSource::Call);
            for function in image.functions.values_mut() {
                function.size_estimated = true;
            }
            super::refine(&mut image);
            assert_eq!(image.functions[&0].size, Some(6));
            assert_eq!(image.functions[&6].size, Some(6));
        }
    }
}
