//! Process-heap blocks and reserved, committed and protected virtual pages.

use crate::emulation::{Access, HEAP_SIZE};

use super::{Runner, Stop};

pub(super) struct HeapBlock {
    size: u64,
    capacity: u64,
}

pub(super) struct Allocation {
    size: u64,
    pages: Vec<Option<u32>>,
}

fn page_range(address: u64, size: u64) -> Option<(u64, u64)> {
    if size == 0 {
        return None;
    }
    address
        .checked_add(size)
        .and_then(|end| end.checked_add(0xfff))
        .map(|end| (address & !0xfff, end & !0xfff))
}

fn access(protection: u32) -> Result<Access, Stop> {
    match protection {
        0x01 | 0x10 => Ok(Access::None),
        0x02 | 0x20 => Ok(Access::Read),
        0x04 | 0x40 => Ok(Access::ReadWrite),
        _ => Err(Stop::Error(format!(
            "unsupported Windows page protection 0x{protection:x}"
        ))),
    }
}

impl Runner<'_> {
    pub(super) fn windows_heap(&mut self, name: &str, args: &[u64]) -> Result<u64, Stop> {
        if args[0] != self.windows_state().heap {
            return Err(Stop::Error(format!(
                "{name}: invalid process heap 0x{:x}",
                args[0]
            )));
        }
        let flags = args[1] as u32;
        let supported = if name == "HeapFree" {
            1
        } else if name == "HeapReAlloc" {
            0x19
        } else {
            9
        };
        if flags & !supported != 0 {
            return Err(Stop::Error(format!(
                "{name}: unsupported flags 0x{flags:x}"
            )));
        }
        if name == "HeapFree" {
            if args[2] != 0 {
                if self
                    .windows_state_mut()
                    .heap_blocks
                    .remove(&args[2])
                    .is_none()
                {
                    return Err(Stop::Error(format!(
                        "HeapFree: unallocated pointer 0x{:x}",
                        args[2]
                    )));
                }
                self.allocations.remove(&args[2]);
            }
            return Ok(1);
        }
        let (old, size) = if name == "HeapReAlloc" {
            (args[2], args[3])
        } else {
            (0, args[2])
        };
        let (old_size, old_capacity) = if name == "HeapReAlloc" {
            let Some(block) = self.windows_state().heap_blocks.get(&old) else {
                return Err(Stop::Error(format!(
                    "HeapReAlloc: unallocated pointer 0x{old:x}"
                )));
            };
            (block.size, block.capacity)
        } else {
            (0, 0)
        };
        let Some(capacity) = size.max(1).checked_add(15).map(|value| value & !15) else {
            return Ok(0);
        };
        let pointer = if old != 0 && capacity <= old_capacity {
            old
        } else if old != 0
            && old.checked_add(old_capacity) == Some(self.heap_next)
            && old
                .checked_add(capacity)
                .is_some_and(|end| end <= self.heap_base + HEAP_SIZE)
        {
            self.heap_next = old + capacity;
            old
        } else if flags & 0x10 != 0 {
            return Ok(0);
        } else {
            self.allocate(capacity)
        };
        if pointer == 0 {
            return Ok(0);
        }
        if old != 0 && pointer != old {
            let bytes = match self.bytes_at(old, Some(old_size.min(size) as usize)) {
                Ok(bytes) => bytes,
                Err(stop) => return Err(stop),
            };
            if let Err(stop) = self.store_bytes(pointer, &bytes) {
                return Err(stop);
            }
        }
        if flags & 8 != 0
            && size > old_size
            && let Err(stop) =
                self.store_bytes(pointer + old_size, &vec![0; (size - old_size) as usize])
        {
            return Err(stop);
        }
        if pointer != old {
            self.windows_state_mut().heap_blocks.remove(&old);
            self.allocations.remove(&old);
        }
        let capacity = if pointer == old {
            capacity.max(old_capacity)
        } else {
            capacity
        };
        self.windows_state_mut()
            .heap_blocks
            .insert(pointer, HeapBlock { size, capacity });
        Ok(pointer)
    }

    fn protect_virtual_pages(
        &mut self,
        address: u64,
        size: u64,
        access: Access,
    ) -> Result<(), Stop> {
        match self
            .machine
            .strict_memory
            .as_mut()
            .expect("strict memory")
            .protect_pages(address, size, access)
        {
            Ok(()) => Ok(()),
            Err(error) => Err(Stop::Error(error)),
        }
    }

    pub(super) fn windows_virtual_memory(&mut self, name: &str, args: &[u64]) -> Result<u64, Stop> {
        if name == "VirtualAlloc" {
            return self.virtual_allocate(args);
        }
        if name == "VirtualFree" && args[2] as u32 == 0x8000 && args[1] != 0 {
            return self.windows_failure(87);
        }
        let address = args[0];
        if name == "VirtualProtect"
            && (self.image.section_at(address).is_some()
                || (self.heap_base..self.heap_base + HEAP_SIZE).contains(&address))
        {
            return Err(Stop::Error(
                "VirtualProtect on image sections or the heap is unsupported".to_owned(),
            ));
        }
        let Some((&base, allocation)) = self
            .windows_state()
            .virtual_allocations
            .range(..=address)
            .next_back()
        else {
            return self.windows_failure(487);
        };
        let allocation_end = base + allocation.size;
        if address >= allocation_end {
            return self.windows_failure(487);
        }
        if name == "VirtualFree" && args[2] as u32 == 0x8000 {
            if address != base {
                return Err(Stop::Error(
                    "VirtualFree with a non-base release address is unsupported".to_owned(),
                ));
            }
            self.windows_state_mut().virtual_allocations.remove(&base);
            self.machine
                .strict_memory
                .as_mut()
                .expect("strict memory")
                .unmap(base);
            self.machine
                .memory
                .retain(|at, _| *at < base || *at >= allocation_end);
            return Ok(1);
        }
        if name == "VirtualFree" && args[2] as u32 != 0x4000 {
            return self.windows_failure(87);
        }
        let size = if name == "VirtualFree" && args[1] == 0 && address == base {
            allocation.size
        } else {
            args[1]
        };
        let Some((start, end)) =
            page_range(address, size).filter(|(_, end)| *end <= allocation_end)
        else {
            return self.windows_failure(87);
        };
        let first = ((start - base) / 0x1000) as usize;
        let last = ((end - base) / 0x1000) as usize;
        if name == "VirtualProtect" {
            let protection = args[2] as u32;
            let permissions = match access(protection) {
                Ok(access) => access,
                Err(stop) => return Err(stop),
            };
            if allocation.pages[first..last].iter().any(Option::is_none) {
                return self.windows_failure(487);
            }
            let old = allocation.pages[first].expect("committed pages");
            if args[3] == 0 {
                return self.windows_failure(998);
            }
            if let Err(stop) = self.check_memory_range(args[3], 4, /* write */ true) {
                return Err(Stop::Error(format!(
                    "VirtualProtect: invalid output pointer 0x{:x}: {stop:?}",
                    args[3]
                )));
            }
            if args[3] < end && args[3].saturating_add(4) > start {
                return Err(Stop::Error(
                    "VirtualProtect output in the changed region is unsupported".to_owned(),
                ));
            }
            if let Err(stop) = self.protect_virtual_pages(start, end - start, permissions) {
                return Err(stop);
            }
            self.windows_state_mut()
                .virtual_allocations
                .get_mut(&base)
                .expect("reserved allocation")
                .pages[first..last]
                .fill(Some(protection));
            for (offset, byte) in old.to_le_bytes().into_iter().enumerate() {
                self.machine.memory.insert(args[3] + offset as u64, byte);
            }
        } else {
            if let Err(stop) = self.protect_virtual_pages(start, end - start, Access::None) {
                return Err(stop);
            }
            self.windows_state_mut()
                .virtual_allocations
                .get_mut(&base)
                .expect("reserved allocation")
                .pages[first..last]
                .fill(None);
            self.machine
                .memory
                .retain(|at, _| *at < start || *at >= end);
        }
        Ok(1)
    }

    fn virtual_allocate(&mut self, args: &[u64]) -> Result<u64, Stop> {
        let flags = args[2] as u32;
        if !matches!(flags, 0x1000 | 0x2000 | 0x3000) {
            return Err(Stop::Error(format!(
                "VirtualAlloc: unsupported allocation flags 0x{flags:x}"
            )));
        }
        let protection = args[3] as u32;
        let permissions = match access(protection) {
            Ok(access) => access,
            Err(stop) => return Err(stop),
        };
        let reserve = flags & 0x2000 != 0 || args[0] == 0;
        let Some((start, end)) = page_range(args[0], args[1]) else {
            return self.windows_failure(87);
        };
        let start = if reserve { start & !0xffff } else { start };
        let size = end - start;
        if size > HEAP_SIZE {
            return self.windows_failure(8);
        }
        let base = if reserve {
            let total: u64 = self
                .windows_state()
                .virtual_allocations
                .values()
                .map(|allocation| allocation.size)
                .sum();
            if total.saturating_add(size) > HEAP_SIZE {
                return self.windows_failure(8);
            }
            let memory = self.machine.strict_memory.as_mut().expect("strict memory");
            let base = if args[0] == 0 {
                match memory.map_zeroed(size, false) {
                    Ok(base) => base,
                    Err(_) => return self.windows_failure(8),
                }
            } else {
                if start == 0 {
                    return self.windows_failure(487);
                }
                if memory.map(start, size, false).is_err() {
                    return self.windows_failure(487);
                }
                start
            };
            if let Err(stop) = self.protect_virtual_pages(base, size, Access::None) {
                return Err(stop);
            }
            self.windows_state_mut().virtual_allocations.insert(
                base,
                Allocation {
                    size,
                    pages: vec![None; (size / 0x1000) as usize],
                },
            );
            base
        } else {
            let Some((&base, allocation)) = self
                .windows_state()
                .virtual_allocations
                .range(..=start)
                .next_back()
            else {
                return self.windows_failure(487);
            };
            if end > base + allocation.size {
                return self.windows_failure(487);
            }
            base
        };
        let pointer = if reserve { base } else { start };
        if flags & 0x1000 != 0 {
            let first = ((pointer - base) / 0x1000) as usize;
            let last = first + (size / 0x1000) as usize;
            if let Err(stop) = self.protect_virtual_pages(pointer, size, permissions) {
                return Err(stop);
            }
            // New reservations are zero-filled; decommit removes stored bytes.
            self.windows_state_mut()
                .virtual_allocations
                .get_mut(&base)
                .expect("reserved allocation")
                .pages[first..last]
                .fill(Some(protection));
        }
        Ok(pointer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_ranges_match_wide_arithmetic_and_symbolic_alignment() {
        use crate::ir::smt::Proofs;

        for address in [0, 1, 0xfff, 0x1000, 0xffff_ffff, u64::MAX - 0xfff, u64::MAX] {
            for size in [0, 1, 2, 0xfff, 0x1000, 0x1001, u64::MAX] {
                let wide_end = u128::from(address) + u128::from(size) + 0xfff;
                let expected = if size != 0 && wide_end <= u128::from(u64::MAX) {
                    Some((
                        address / 0x1000 * 0x1000,
                        (wide_end / 0x1000 * 0x1000) as u64,
                    ))
                } else {
                    None
                };
                assert_eq!(page_range(address, size), expected, "{address:x} {size:x}");
            }
        }
        if !Proofs::available() {
            return;
        }
        let mut proofs = Proofs::default();
        let mask = crate::ir::smt::constant(!0xfff);
        let page = crate::ir::smt::constant(0x1000);
        let adjustment = crate::ir::smt::constant(0xfff);
        let end = format!("(bvadd (bvadd r0 r1) {adjustment})");
        proofs.predicate(
            "page start rounds down",
            &format!("(bvand r0 {mask})"),
            &format!("(bvmul (bvudiv r0 {page}) {page})"),
        );
        proofs.predicate(
            "page end rounds up after checked addition",
            &format!("(bvand {end} {mask})"),
            &format!("(bvmul (bvudiv {end} {page}) {page})"),
        );
        proofs.counterexample(
            "page end cannot round down without the adjustment",
            &format!("(bvand {end} {mask})"),
            &format!("(bvand (bvadd r0 r1) {mask})"),
        );
        proofs.check();
    }
}

#[cfg(kani)]
mod proofs {
    #[kani::proof]
    fn page_ranges_cover_the_request() {
        let address: u64 = kani::any();
        let size: u64 = kani::any();
        match super::page_range(address, size) {
            Some((start, end)) => {
                let request_end = address + size;
                assert!(
                    start % 0x1000 == 0 && end % 0x1000 == 0,
                    "the range is page aligned"
                );
                assert!(
                    start <= address && request_end <= end,
                    "the range covers the request"
                );
                assert!(
                    address - start < 0x1000,
                    "no page precedes the first touched page"
                );
                assert!(
                    end - request_end < 0x1000,
                    "no page follows the last touched page"
                );
            }
            None => assert!(
                size == 0
                    || address
                        .checked_add(size)
                        .and_then(|end| end.checked_add(0xfff))
                        .is_none(),
                "only empty or overflowing requests are rejected"
            ),
        }
    }
}
