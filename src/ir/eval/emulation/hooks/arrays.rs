//! Sorting and searching arrays through comparison callbacks.

use super::{CallKind, Convention, HEAP_SIZE, Runner, Stop};

impl Runner<'_> {
    fn element_address(&self, base: u64, index: u64, size: u64) -> Result<u64, Stop> {
        let Some(offset) = index.checked_mul(size) else {
            return Err(Stop::Error("array element offset overflows".to_owned()));
        };
        base.checked_add(offset)
            .ok_or_else(|| Stop::Error("array element address overflows".to_owned()))
    }

    fn compare_elements(
        &mut self,
        comparator: u64,
        left: u64,
        right: u64,
        depth: usize,
    ) -> Result<i32, Stop> {
        let result = self.call_callback(comparator, &[left, right], depth)?;
        Ok(result as u32 as i32)
    }

    fn swap_elements(&mut self, left: u64, right: u64, size: u64) -> Result<(), Stop> {
        if left == right {
            return Ok(());
        }
        for offset in 0..size {
            let Some(left_address) = left.checked_add(offset) else {
                return Err(Stop::Error("array element address overflows".to_owned()));
            };
            let Some(right_address) = right.checked_add(offset) else {
                return Err(Stop::Error("array element address overflows".to_owned()));
            };
            let left_byte = self.read_byte(left_address)?;
            let right_byte = self.read_byte(right_address)?;
            self.write_byte(left_address, right_byte)?;
            self.write_byte(right_address, left_byte)?;
        }
        Ok(())
    }

    pub(super) fn sort(
        &mut self,
        base: u64,
        convention: Convention,
        kind: CallKind,
        depth: usize,
    ) -> Result<u64, Stop> {
        let count = self.argument(1, convention, kind)?;
        let size = self.argument(2, convention, kind)?;
        let comparator = self.argument(3, convention, kind)?;
        let Some(total) = count.checked_mul(size) else {
            return Err(Stop::Error("qsort array size overflows".to_owned()));
        };
        if total > HEAP_SIZE {
            return Err(Stop::Error("qsort array exceeds 16 MiB".to_owned()));
        }
        if count < 2 || size == 0 {
            return Ok(0);
        }
        self.check_memory_range(base, total, true)?;
        let mut root = count / 2;
        while root != 0 {
            root -= 1;
            self.sift_down(base, root, count, size, comparator, depth)?;
        }
        let mut end = count;
        while end > 1 {
            self.swap_elements(base, self.element_address(base, end - 1, size)?, size)?;
            end -= 1;
            self.sift_down(base, 0, end, size, comparator, depth)?;
        }
        Ok(0)
    }

    fn sift_down(
        &mut self,
        base: u64,
        mut root: u64,
        end: u64,
        size: u64,
        comparator: u64,
        depth: usize,
    ) -> Result<(), Stop> {
        loop {
            let Some(child) = root.checked_mul(2).and_then(|value| value.checked_add(1)) else {
                return Err(Stop::Error("qsort index overflows".to_owned()));
            };
            if child >= end {
                return Ok(());
            }
            let right = child + 1;
            let child = if right < end {
                let left_address = self.element_address(base, child, size)?;
                let right_address = self.element_address(base, right, size)?;
                if self.compare_elements(comparator, left_address, right_address, depth)? < 0 {
                    right
                } else {
                    child
                }
            } else {
                child
            };
            let root_address = self.element_address(base, root, size)?;
            let child_address = self.element_address(base, child, size)?;
            if self.compare_elements(comparator, root_address, child_address, depth)? >= 0 {
                return Ok(());
            }
            self.swap_elements(root_address, child_address, size)?;
            root = child;
        }
    }

    pub(super) fn binary_search(
        &mut self,
        key: u64,
        convention: Convention,
        kind: CallKind,
        depth: usize,
    ) -> Result<u64, Stop> {
        let base = self.argument(1, convention, kind)?;
        let count = self.argument(2, convention, kind)?;
        let size = self.argument(3, convention, kind)?;
        let comparator = self.argument(4, convention, kind)?;
        let Some(total) = count.checked_mul(size) else {
            return Err(Stop::Error("bsearch array size overflows".to_owned()));
        };
        if total > HEAP_SIZE {
            return Err(Stop::Error("bsearch array exceeds 16 MiB".to_owned()));
        }
        if size == 0 {
            return Ok(0);
        }
        self.check_memory_range(base, total, false)?;
        let mut lower = 0;
        let mut upper = count;
        while lower < upper {
            let middle = lower + (upper - lower) / 2;
            let element = self.element_address(base, middle, size)?;
            match self.compare_elements(comparator, key, element, depth)? {
                0 => return Ok(element),
                value if value < 0 => upper = middle,
                _ => lower = middle + 1,
            }
        }
        Ok(0)
    }
}
