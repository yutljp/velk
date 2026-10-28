//! Sparse memory backed by loaded sections and bounded zero-filled areas.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

use crate::loader::Image;

use super::MemoryChange;

const DEFAULT_HEAP_BASE: u64 = 0x1000_0000;
pub(crate) const HEAP_SIZE: u64 = 1 << 24;
const TLS_SIZE: u64 = 0x1000;
const STACK_SIZE: u64 = 1 << 20;

pub(crate) struct Memory<'a> {
    image: &'a Image,
    pub(crate) heap_base: u64,
    heap_end: u64,
    pub(crate) tls_base: u64,
    tls_end: u64,
    stack_start: u64,
    stack_end: u64,
    pub(crate) fault: RefCell<Option<String>>,
}

impl<'a> Memory<'a> {
    pub(crate) fn new(image: &'a Image) -> Result<Self, String> {
        Self::with_tls(image, None)
    }

    pub(crate) fn with_tls(image: &'a Image, base: Option<u64>) -> Result<Self, String> {
        let stack_end = crate::ir::eval::stack_top(image.isa) + 0x1000;
        let stack_start = stack_end - STACK_SIZE;
        let mut ranges = vec![(stack_start, stack_end)];
        for section in &image.sections {
            if !section.loaded || section.size == 0 {
                continue;
            }
            let Some(end) = section.vaddr.checked_add(section.size) else {
                return Err(format!(
                    "section {} overflows the address space",
                    section.name
                ));
            };
            if section.vaddr < stack_end && end > stack_start {
                return Err(format!("section {} overlaps the stack", section.name));
            }
            ranges.push((section.vaddr, end));
        }
        ranges.sort_unstable();
        let mut heap_base = DEFAULT_HEAP_BASE;
        let limit = if crate::arch::pointer_bytes(image.isa) == 4 {
            1u64 << 32
        } else {
            stack_start
        };
        for &(start, end) in &ranges {
            let Some(heap_end) = heap_base.checked_add(HEAP_SIZE) else {
                return Err("heap address overflows".to_owned());
            };
            if start < heap_end && end > heap_base {
                let Some(next) = end.checked_add(0xffff) else {
                    return Err("no address range is available for the heap".to_owned());
                };
                heap_base = next & !0xffff;
            }
        }
        let Some(heap_end) = heap_base.checked_add(HEAP_SIZE).filter(|end| *end <= limit) else {
            return Err("no address range is available for the heap".to_owned());
        };
        ranges.push((heap_base, heap_end));
        ranges.sort_unstable();
        let mut tls_base = base.unwrap_or(0x2000_0000);
        for &(start, end) in &ranges {
            let Some(tls_end) = tls_base.checked_add(TLS_SIZE) else {
                return Err("thread-local range overflows".to_owned());
            };
            if start < tls_end && end > tls_base {
                if base.is_some() {
                    return Err("thread-local range overlaps mapped memory".to_owned());
                }
                let Some(next) = end.checked_add(TLS_SIZE - 1) else {
                    return Err("no address range is available for thread-local storage".to_owned());
                };
                tls_base = next & !(TLS_SIZE - 1);
            }
        }
        let Some(tls_end) = tls_base.checked_add(TLS_SIZE).filter(|end| *end <= limit) else {
            return Err("thread-local range exceeds the address space".to_owned());
        };
        Ok(Self {
            tls_base,
            tls_end,
            image,
            heap_base,
            heap_end,
            stack_start,
            stack_end,
            fault: RefCell::new(None),
        })
    }

    fn zero_area(&self, address: u64) -> bool {
        (self.tls_base..self.tls_end).contains(&address)
            || (self.heap_base..self.heap_end).contains(&address)
            || (self.stack_start..self.stack_end).contains(&address)
    }

    pub(crate) fn check(&self, address: u64, size: u64, write: bool) -> bool {
        let Some(end) = address.checked_add(size) else {
            self.fail(format!("memory range overflows at 0x{address:x}"));
            return false;
        };
        let mut at = address;
        while at < end {
            if self.zero_area(at) {
                let limit = if (self.heap_base..self.heap_end).contains(&at) {
                    self.heap_end
                } else if (self.tls_base..self.tls_end).contains(&at) {
                    self.tls_end
                } else {
                    self.stack_end
                };
                at = end.min(limit);
                continue;
            }
            let Some(section) = self.image.section_at(at) else {
                self.fail(format!(
                    "unmapped memory {} at 0x{at:x}",
                    if write { "write" } else { "read" }
                ));
                return false;
            };
            if write && (section.read_only || section.executable) {
                self.fail(format!(
                    "write to protected section {} at 0x{at:x}",
                    section.name
                ));
                return false;
            }
            at = end.min(section.vaddr.saturating_add(section.size));
        }
        true
    }

    pub(crate) fn fail(&self, error: String) {
        let mut fault = self.fault.borrow_mut();
        if fault.is_none() {
            *fault = Some(error);
        }
    }

    pub(crate) fn byte(&self, address: u64) -> u8 {
        if !self.check(address, 1, /* write */ false) {
            return 0;
        }
        if self.zero_area(address) {
            return 0;
        }
        let Some(section) = self.image.section_at(address) else {
            return 0;
        };
        let Some(offset) = section.file_offset else {
            return 0;
        };
        let displacement = address - section.vaddr;
        if displacement >= self.image.section_file_size(section) {
            return 0;
        }
        let offset = offset.checked_add(displacement);
        match offset.and_then(|offset| self.image.read(offset, 1)) {
            Some(bytes) => bytes[0],
            None => {
                self.fail(format!("missing section data at 0x{address:x}"));
                0
            }
        }
    }

    pub(crate) fn changes(
        &self,
        before: &HashMap<u64, u8>,
        after: &HashMap<u64, u8>,
    ) -> Vec<MemoryChange> {
        use std::fmt::Write as _;
        let mut changed = BTreeMap::new();
        for (&address, &byte) in after {
            let initial = before
                .get(&address)
                .copied()
                .unwrap_or_else(|| self.byte(address));
            if initial != byte {
                changed.insert(address, byte);
            }
        }
        let mut regions: Vec<MemoryChange> = Vec::new();
        for (address, byte) in changed {
            if let Some(last) = regions.last_mut()
                && crate::addr::parse(&last.address)
                    .and_then(|start| start.checked_add(last.bytes.len() as u64))
                    == Some(address)
            {
                last.bytes.push(byte);
                let _ = write!(last.hex, " {byte:02x}");
                continue;
            }
            regions.push(MemoryChange {
                address: crate::addr::format(address),
                bytes: vec![byte],
                hex: format!("{byte:02x}"),
            });
        }
        regions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_bytes_after_file_data_are_zero_filled() {
        let mut image =
            Image::from_code(crate::loader::Isa::X86_64, 0x1000, vec![1, 2, 3, 4, 99, 88]);
        image.sections[0].size = 8;
        image.sections[0].file_size = 4;
        let memory = Memory::new(&image).expect("image outside stack and heap");
        assert_eq!(memory.byte(0x1003), 4);
        assert_eq!(memory.byte(0x1004), 0);
        assert_eq!(memory.byte(0x1007), 0);
        assert!(memory.fault.borrow().is_none());
        assert!(!memory.check(0x1007, 2, /* write */ false));
        assert!(memory.fault.borrow().as_ref().unwrap().contains("0x1008"));
    }
    #[test]
    fn heap_avoids_images_at_the_default_heap_address() {
        let address = DEFAULT_HEAP_BASE + 0x1000;
        let image = Image::from_code(crate::loader::Isa::I386, address, vec![0xc3]);
        let memory = Memory::new(&image).expect("a free range follows the image");
        assert!(memory.heap_base > address);
        assert_eq!(memory.byte(address), 0xc3);
        assert_eq!(memory.byte(memory.heap_base), 0);
        assert!(memory.check(memory.heap_base, HEAP_SIZE, /* write */ true));
        assert!(!memory.check(address, 1, /* write */ true));
    }
}

#[cfg(test)]
mod tls_tests {
    use super::*;

    #[test]
    fn thread_local_storage_avoids_sections_and_checks_both_boundaries() {
        for isa in [
            crate::loader::Isa::X86_64,
            crate::loader::Isa::I386,
            crate::loader::Isa::AArch64,
        ] {
            let image = Image::from_code(isa, 0x2000_0000, vec![0xc3]);
            let memory = Memory::new(&image).expect("TLS follows the section");
            assert_eq!(memory.tls_base, 0x2000_1000);
            assert!(memory.check(memory.tls_base, TLS_SIZE, /* write */ true));
            assert!(!memory.check(memory.tls_base - 1, 1, /* write */ false));
            assert!(!memory.check(memory.tls_base + TLS_SIZE - 1, 2, /* write */ true));
            assert!(Memory::with_tls(&image, Some(0x2000_0000)).is_err());
            assert!(Memory::with_tls(&image, Some(DEFAULT_HEAP_BASE)).is_err());
            assert!(Memory::with_tls(&image, Some(crate::ir::eval::stack_top(isa))).is_err());
            assert!(Memory::with_tls(&image, Some(u64::MAX)).is_err());
            if isa == crate::loader::Isa::I386 {
                assert!(Memory::with_tls(&image, Some((1u64 << 32) - TLS_SIZE + 1)).is_err());
            }
        }
    }
}
