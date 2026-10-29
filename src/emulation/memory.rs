//! Sparse memory backed by loaded sections and bounded zero-filled areas.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::loader::Image;

use super::MemoryChange;

const DEFAULT_HEAP_BASE: u64 = 0x1000_0000;
pub(crate) const HEAP_SIZE: u64 = 1 << 24;
const TLS_SIZE: u64 = 0x1000;
const STACK_SIZE: u64 = 1 << 20;

struct Region {
    start: u64,
    end: u64,
    read_only: bool,
    pages: Vec<Access>,
}

#[derive(Clone, Copy)]
pub(crate) enum Access {
    None,
    Read,
    ReadWrite,
}

pub(crate) struct Memory<'a> {
    image: &'a Image,
    pub(crate) heap_base: u64,
    heap_end: u64,
    pub(crate) tls_base: u64,
    tls_end: u64,
    stack_start: u64,
    stack_end: u64,
    pub(crate) fault: RefCell<Option<String>>,
    regions: Vec<Region>,
    watched_reads: Vec<(u64, u64, String)>,
    pub(crate) observed_reads: RefCell<BTreeSet<String>>,
}

impl<'a> Memory<'a> {
    pub(crate) fn new(image: &'a Image) -> Result<Self, String> {
        Self::with_tls(image, None)
    }

    pub(crate) fn with_tls(image: &'a Image, base: Option<u64>) -> Result<Self, String> {
        let tls_size = if image.format == crate::loader::Format::Pe
            && matches!(
                image.isa,
                crate::loader::Isa::X86_64 | crate::loader::Isa::I386
            ) {
            0x2000
        } else {
            TLS_SIZE
        };
        let stack_end = crate::ir::eval::stack_top(image.isa) + 0x1000;
        let stack_start = stack_end - STACK_SIZE;
        let mut ranges = vec![(stack_start, stack_end)];
        for section in Self::mappings(image) {
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
            let Some(tls_end) = tls_base.checked_add(tls_size) else {
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
        let Some(tls_end) = tls_base.checked_add(tls_size).filter(|end| *end <= limit) else {
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
            regions: Vec::new(),
            watched_reads: Vec::new(),
            observed_reads: RefCell::new(BTreeSet::new()),
        })
    }

    pub(crate) fn map(&mut self, address: u64, size: u64, read_only: bool) -> Result<(), String> {
        let limit = if crate::arch::pointer_bytes(self.image.isa) == 4 {
            1u64 << 32
        } else {
            self.stack_start
        };
        let Some(end) = address.checked_add(size).filter(|end| *end <= limit) else {
            return Err(format!(
                "mapping at 0x{address:x} exceeds the address space"
            ));
        };
        if size == 0 || size > HEAP_SIZE {
            return Err(format!("invalid mapping size at 0x{address:x}: {size}"));
        }
        if self
            .ranges()
            .iter()
            .any(|&(start, limit)| address < limit && end > start)
        {
            return Err(format!("mapping at 0x{address:x} overlaps mapped memory"));
        }
        self.regions.push(Region {
            start: address,
            end,
            read_only,
            pages: Vec::new(),
        });
        Ok(())
    }

    pub(crate) fn map_zeroed(&mut self, size: u64, read_only: bool) -> Result<u64, String> {
        let mut ranges = self.ranges();
        ranges.sort_unstable();
        let mut address = 0x3000_0000u64;
        for (start, end) in ranges {
            if address < end && address.saturating_add(size) > start {
                let Some(next) = end.checked_add(0xffff) else {
                    return Err("no address range is available for a mapping".to_owned());
                };
                address = next & !0xffff;
            }
        }
        match self.map(address, size, read_only) {
            Ok(()) => Ok(address),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn protect_pages(
        &mut self,
        address: u64,
        size: u64,
        access: Access,
    ) -> Result<(), String> {
        let Some(end) = address.checked_add(size) else {
            return Err(format!("protection range overflows at 0x{address:x}"));
        };
        let Some(region) = self.regions.iter_mut().find(|region| {
            region.start <= address && end <= region.end && region.start & 0xfff == 0
        }) else {
            return Err(format!("protection range at 0x{address:x} is not mapped"));
        };
        if size == 0 || address & 0xfff != 0 || end & 0xfff != 0 {
            return Err(format!(
                "protection range at 0x{address:x} is not page aligned"
            ));
        }
        if region.pages.is_empty() {
            region.pages.resize(
                ((region.end - region.start).div_ceil(0x1000)) as usize,
                if region.read_only {
                    Access::Read
                } else {
                    Access::ReadWrite
                },
            );
        }
        let first = ((address - region.start) / 0x1000) as usize;
        let last = ((end - region.start) / 0x1000) as usize;
        region.pages[first..last].fill(access);
        Ok(())
    }

    pub(crate) fn unmap(&mut self, address: u64) {
        self.regions.retain(|region| region.start != address);
    }

    fn ranges(&self) -> Vec<(u64, u64)> {
        let mut ranges = vec![
            (self.heap_base, self.heap_end),
            (self.tls_base, self.tls_end),
            (self.stack_start, self.stack_end),
        ];
        for section in Self::mappings(self.image) {
            if section.loaded {
                ranges.push((section.vaddr, section.vaddr.saturating_add(section.size)));
            }
        }
        for region in &self.regions {
            ranges.push((region.start, region.end));
        }
        ranges
    }

    pub(crate) fn watch_read(&mut self, address: u64, size: u64, name: &str) {
        self.watched_reads
            .push((address, address.saturating_add(size), name.to_owned()));
    }

    fn zero_area(&self, address: u64) -> bool {
        (self.tls_base..self.tls_end).contains(&address)
            || (self.heap_base..self.heap_end).contains(&address)
            || (self.stack_start..self.stack_end).contains(&address)
    }

    fn mappings(image: &Image) -> &[crate::loader::Section] {
        if image.load_segments.is_empty() {
            &image.sections
        } else {
            &image.load_segments
        }
    }

    fn mapping_at(&self, address: u64) -> Option<&crate::loader::Section> {
        Self::mappings(self.image).iter().rev().find(|section| {
            section.loaded && address >= section.vaddr && address - section.vaddr < section.size
        })
    }

    pub(crate) fn check(&self, address: u64, size: u64, write: bool) -> bool {
        let Some(end) = address.checked_add(size) else {
            self.fail(format!("memory range overflows at 0x{address:x}"));
            return false;
        };
        if !write && size != 0 {
            for (start, limit, name) in &self.watched_reads {
                if address < *limit && end > *start {
                    self.observed_reads.borrow_mut().insert(name.clone());
                }
            }
        }
        let mut at = address;
        while at < end {
            if let Some(region) = self
                .regions
                .iter()
                .find(|region| region.start <= at && at < region.end)
            {
                let access = region.pages.get(((at - region.start) / 0x1000) as usize);
                let permitted = match access {
                    Some(Access::None) => false,
                    Some(Access::Read) => !write,
                    Some(Access::ReadWrite) => true,
                    None => !write || !region.read_only,
                };
                if !permitted {
                    self.fail(format!(
                        "{} protected mapping at 0x{at:x}",
                        if write { "write to" } else { "read from" }
                    ));
                    return false;
                }
                at = if region.pages.is_empty() {
                    end.min(region.end)
                } else {
                    end.min(region.end)
                        .min((at & !0xfff).saturating_add(0x1000))
                };
                continue;
            }
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
            let Some(section) = self.mapping_at(at) else {
                self.fail(format!(
                    "unmapped memory {} at 0x{at:x}",
                    if write { "write" } else { "read" }
                ));
                return false;
            };
            if write
                && (section.read_only
                    || (self.image.load_segments.is_empty() && section.executable))
            {
                self.fail(format!(
                    "write to protected section {} at 0x{at:x}",
                    section.name
                ));
                return false;
            }
            let mut limit = section.vaddr.saturating_add(section.size);
            for next in Self::mappings(self.image) {
                if next.loaded && next.vaddr > at {
                    limit = limit.min(next.vaddr);
                }
            }
            at = end.min(limit);
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
        if self.zero_area(address)
            || self
                .regions
                .iter()
                .any(|region| region.start <= address && address < region.end)
        {
            return 0;
        }
        let Some(section) = self.mapping_at(address) else {
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

    #[test]
    fn page_protections_check_every_page_and_unmap_the_reservation() {
        let image = Image::from_code(crate::loader::Isa::I386, 0x1000, vec![0xc3]);
        let mut memory = Memory::new(&image).expect("image outside stack and heap");
        let base = memory
            .map_zeroed(0x3000, false)
            .expect("free virtual memory");
        memory
            .protect_pages(base + 0x1000, 0x1000, Access::Read)
            .unwrap();
        assert!(memory.check(base, 0x3000, /* write */ false));
        assert!(!memory.check(base + 0xfff, 2, /* write */ true));
        memory.fault.borrow_mut().take();
        assert!(memory.check(base, 0x1000, /* write */ true));
        assert!(memory.check(base + 0x2000, 0x1000, /* write */ true));
        memory
            .protect_pages(base + 0x2000, 0x1000, Access::None)
            .unwrap();
        assert!(!memory.check(base, 0x3000, /* write */ false));
        memory.fault.borrow_mut().take();
        assert!(memory.protect_pages(base, u64::MAX, Access::Read).is_err());
        assert!(
            memory
                .protect_pages(base + 1, 0x1000, Access::Read)
                .is_err()
        );
        memory.unmap(base);
        assert!(!memory.check(base, 1, /* write */ false));
        assert!(memory.map(base, 0x3000, false).is_ok());
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
