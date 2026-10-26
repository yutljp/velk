//! Bounded decoding of Itanium language-specific exception tables.

use std::collections::BTreeSet;

use crate::loader::Image;
use crate::loader::classes;

#[derive(Debug, Clone)]
pub(crate) struct Region {
    pub function: u64,
    pub start: u64,
    pub end: u64,
    pub landing_pad: u64,
    pub catches: Vec<String>,
    pub cleanup: bool,
}

struct Reader<'a> {
    image: &'a Image,
    at: u64,
    end: u64,
}

impl<'a> Reader<'a> {
    fn new(image: &'a Image, at: u64) -> Option<Self> {
        let Some(section) = image.section_at(at) else {
            return None;
        };
        let Some(end) = section.vaddr.checked_add(section.size) else {
            return None;
        };
        Some(Self { image, at, end })
    }

    fn take(&mut self, size: u64) -> Option<u64> {
        let Some(end) = self.at.checked_add(size) else {
            return None;
        };
        if end > self.end {
            return None;
        }
        let value = classes::word(self.image, self.at, size);
        self.at = end;
        value
    }

    fn uleb(&mut self) -> Option<u64> {
        let mut value = 0;
        for shift in (0..64).step_by(7) {
            let Some(byte) = self.take(1) else {
                return None;
            };
            if shift == 63 && byte > 1 {
                return None;
            }
            value |= (byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    fn sleb(&mut self) -> Option<i64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let Some(byte) = self.take(1) else {
                return None;
            };
            if shift == 63 && byte != 0 && byte != 0x7f {
                return None;
            }
            value |= (byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                if byte & 0x40 != 0 && shift < 63 {
                    value |= u64::MAX << (shift + 7);
                }
                return Some(value as i64);
            }
        }
        None
    }

    fn encoded(&mut self, encoding: u8) -> Option<u64> {
        let place = self.at;
        let value = match encoding & 0x0f {
            0 => self.take(u64::from(crate::arch::pointer_bytes(self.image.isa))),
            1 => self.uleb(),
            2 => self.take(2),
            3 => self.take(4),
            4 | 12 => self.take(8),
            9 => self.sleb().map(|value| value as u64),
            10 => self.take(2).map(|value| value as i16 as i64 as u64),
            11 => self.take(4).map(|value| value as i32 as i64 as u64),
            _ => None,
        };
        let Some(value) = value else {
            return None;
        };
        if value == 0 {
            return Some(0);
        }
        match encoding & 0x70 {
            0 => Some(value),
            0x10 if encoding & 0x08 != 0 => place.checked_add_signed(value as i64),
            0x10 => place.checked_add(value),
            _ => None,
        }
    }
}

pub(super) fn read(image: &Image, lsda: u64, function: u64) -> Vec<Region> {
    let mut regions = Vec::new();
    let Some(mut reader) = Reader::new(image, lsda) else {
        return regions;
    };
    let Some(start_encoding) = reader.take(1) else {
        return regions;
    };
    let base = if start_encoding == 0xff {
        function
    } else {
        let Some(mut base) = reader.encoded(start_encoding as u8) else {
            return regions;
        };
        if start_encoding & 0x80 != 0 {
            let Some(pointer) = classes::word(
                image,
                base,
                u64::from(crate::arch::pointer_bytes(image.isa)),
            ) else {
                return regions;
            };
            base = pointer;
        }
        base
    };
    let Some(type_encoding) = reader.take(1) else {
        return regions;
    };
    let type_table = if type_encoding == 0xff {
        None
    } else {
        let Some(offset) = reader.uleb() else {
            return regions;
        };
        let Some(table) = reader
            .at
            .checked_add(offset)
            .filter(|end| *end <= reader.end)
        else {
            return regions;
        };
        Some(table)
    };
    let (Some(encoding), Some(size)) = (reader.take(1), reader.uleb()) else {
        return regions;
    };
    // Call-site entries contain offsets, never relative or indirect pointers.
    if encoding & 0xf0 != 0 {
        return regions;
    }
    let Some(actions) = reader.at.checked_add(size).filter(|end| *end <= reader.end) else {
        return regions;
    };
    reader.end = actions;
    while reader.at < actions {
        let (Some(start), Some(size), Some(pad), Some(action)) = (
            reader.encoded(encoding as u8),
            reader.encoded(encoding as u8),
            reader.encoded(encoding as u8),
            reader.uleb(),
        ) else {
            break;
        };
        if pad == 0 || size == 0 {
            continue;
        }
        let (Some(start), Some(landing_pad)) = (base.checked_add(start), base.checked_add(pad))
        else {
            continue;
        };
        let Some(end) = start.checked_add(size) else {
            continue;
        };
        if !image
            .section_at(landing_pad)
            .is_some_and(|section| section.executable)
            || !image.section_at(start).is_some_and(|section| {
                section.executable && end <= section.vaddr.saturating_add(section.size)
            })
        {
            continue;
        }
        let mut region = Region {
            function,
            start,
            end,
            landing_pad,
            catches: Vec::new(),
            cleanup: action == 0,
        };
        if action != 0 {
            let Some(at) = actions.checked_add(action - 1) else {
                continue;
            };
            decode_actions(
                image,
                at,
                actions,
                type_table,
                type_encoding as u8,
                &mut region,
            );
        }
        regions.push(region);
    }
    regions
}

fn decode_actions(
    image: &Image,
    mut at: u64,
    actions: u64,
    types: Option<u64>,
    encoding: u8,
    region: &mut Region,
) {
    let mut visited = BTreeSet::new();
    for _ in 0..4096 {
        if at < actions || types.is_some_and(|end| at >= end) || !visited.insert(at) {
            break;
        }
        let Some(mut reader) = Reader::new(image, at) else {
            break;
        };
        if let Some(end) = types {
            reader.end = reader.end.min(end);
        }
        let Some(filter) = reader.sleb() else {
            break;
        };
        let next_at = reader.at;
        let Some(next) = reader.sleb() else {
            break;
        };
        if filter == 0 {
            region.cleanup = true;
        } else if filter > 0 {
            let name = catch_type(image, types, encoding, filter as u64);
            region
                .catches
                .push(name.unwrap_or_else(|| format!("unknown type #{filter}")));
        } else {
            region.catches.push("exception specification".to_owned());
        }
        if next == 0 {
            break;
        }
        let Some(next) = next_at.checked_add_signed(next) else {
            break;
        };
        at = next;
    }
}

fn catch_type(image: &Image, table: Option<u64>, encoding: u8, filter: u64) -> Option<String> {
    let size = match encoding & 0x0f {
        0 => u64::from(crate::arch::pointer_bytes(image.isa)),
        2 | 10 => 2,
        3 | 11 => 4,
        4 | 12 => 8,
        _ => return None,
    };
    let Some(at) = filter
        .checked_mul(size)
        .and_then(|offset| table.and_then(|table| table.checked_sub(offset)))
    else {
        return None;
    };
    let Some(mut reader) = Reader::new(image, at) else {
        return None;
    };
    let Some(mut info) = reader.encoded(encoding) else {
        return None;
    };
    if info == 0 {
        return Some("...".to_owned());
    }
    if encoding & 0x80 != 0 {
        if let Some(name) = image.imports.get(&info) {
            let name = crate::loader::demangle_name(name);
            return name
                .trim_start_matches('_')
                .strip_prefix("typeinfo for ")
                .map(str::to_owned);
        }
        let Some(pointer) = classes::word(
            image,
            info,
            u64::from(crate::arch::pointer_bytes(image.isa)),
        ) else {
            return None;
        };
        info = pointer;
    }
    classes::itanium_type_name(image, info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::Isa;

    #[test]
    fn leb_overflow_and_unterminated_values_are_rejected() {
        for bytes in [
            vec![0xff; 10],
            vec![0x80; 10],
            vec![0x80; 9].into_iter().chain([2]).collect(),
        ] {
            let image = Image::from_code(Isa::X86_64, 0x1000, bytes);
            assert_eq!(Reader::new(&image, 0x1000).unwrap().uleb(), None);
        }
        let image = Image::from_code(Isa::X86_64, 0x1000, vec![0x80; 10]);
        assert_eq!(Reader::new(&image, 0x1000).unwrap().sleb(), None);
    }
}

#[cfg(test)]
mod malformed {
    use super::*;
    use crate::loader::Isa;

    fn image(bytes: Vec<u8>) -> Image {
        Image::from_code(Isa::X86_64, 0x1000, bytes)
    }

    #[test]
    fn bad_lengths_and_cyclic_actions_do_not_escape_the_section() {
        // LPStart omitted, type table omitted, uleb sites, one protected byte.
        for bytes in [
            vec![0xff, 0xff, 1, 0xff],
            vec![0xff, 0xff, 1, 4, 0xff, 0xff, 0xff, 0xff],
        ] {
            assert!(read(&image(bytes), 0x1000, 0x1000).is_empty());
        }
        let mut bytes = vec![0xff, 0xff, 1, 4, 0, 1, 1, 1, 0, 0x7f];
        bytes.resize(32, 0);
        let image = image(bytes);
        let regions = read(&image, 0x1000, 0x1000);
        assert_eq!(regions.len(), 1);
        assert!(regions[0].cleanup);
        assert!(regions[0].catches.is_empty());
    }

    #[test]
    fn signed_relative_encodings_check_overflow() {
        let image = image(vec![0xff; 8]);
        let mut reader = Reader::new(&image, 0x1000).unwrap();
        assert_eq!(reader.encoded(0x1c), Some(0xfff));
        let mut reader = Reader::new(&image, 0x1000).unwrap();
        assert_eq!(reader.encoded(0x14), None);
    }
}
