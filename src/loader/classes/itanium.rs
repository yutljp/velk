//! Itanium class type descriptors and address-point headers.

use std::collections::BTreeMap;

use super::references;

use super::{Base, Class, Vtable};
use crate::loader::Image;

pub(crate) fn type_name(image: &Image, address: u64) -> Option<String> {
    let width = u64::from(crate::arch::pointer_bytes(image.isa));
    let Some(at) = address.checked_add(width) else {
        return None;
    };
    let Some(name) = super::word(image, at, width).and_then(|pointer| {
        let pointer = if width == 8 {
            pointer & !(1 << 63)
        } else {
            pointer
        };
        super::text(image, pointer)
    }) else {
        return None;
    };
    let mangled = format!("_ZTS{}", name.trim_start_matches('*'));
    let demangled = crate::loader::demangle_name(&mangled);
    demangled
        .strip_prefix("typeinfo name for ")
        .map(str::to_owned)
}

pub(super) fn read(image: &Image) -> Vec<Class> {
    let width = u64::from(crate::arch::pointer_bytes(image.isa));
    let names = references::read(image);
    let mut classes = BTreeMap::<u64, Class>::new();
    for section in &image.sections {
        if !section.loaded || section.executable || section.file_offset.is_none() {
            continue;
        }
        let Some(bytes) = image.read_vaddr(section.vaddr, section.size) else {
            continue;
        };
        for (index, chunk) in bytes.chunks_exact(width as usize).enumerate() {
            let Some(address) = section.vaddr.checked_add(index as u64 * width) else {
                break;
            };
            let pointer = unsigned(chunk);
            let kind = names.get(&address).or_else(|| {
                pointer
                    .checked_sub(2 * width)
                    .and_then(|address| image.data_symbols.get(&address))
            });
            let Some(kind) = kind else {
                continue;
            };
            let kind = kind.trim_start_matches('_');
            let multiple = kind == "ZTVN10__cxxabiv121__vmi_class_type_infoE";
            let single = kind == "ZTVN10__cxxabiv120__si_class_type_infoE";
            if !multiple && !single && kind != "ZTVN10__cxxabiv117__class_type_infoE" {
                continue;
            }
            let Some(name) = type_name(image, address) else {
                continue;
            };
            let mut bases = Vec::new();
            if single {
                let Some(base) = address
                    .checked_add(2 * width)
                    .and_then(|at| super::word(image, at, width))
                else {
                    continue;
                };
                let Some(name) = type_name(image, base) else {
                    continue;
                };
                bases.push(Base {
                    name,
                    offset: Some(0),
                    is_virtual: false,
                    is_public: true,
                    vtable_offset: None,
                    vbtable: None,
                });
            }
            if multiple {
                let Some(count) = address
                    .checked_add(2 * width + 4)
                    .and_then(|at| super::word(image, at, 4))
                else {
                    continue;
                };
                if count > 4096 {
                    continue;
                }
                let mut valid = true;
                for index in 0..count {
                    let Some(at) = address.checked_add(2 * width + 8 + index * 2 * width) else {
                        valid = false;
                        break;
                    };
                    let (Some(base), Some(flags)) = (
                        super::word(image, at, width),
                        super::word(image, at.saturating_add(width), width),
                    ) else {
                        valid = false;
                        break;
                    };
                    let Some(name) = type_name(image, base) else {
                        valid = false;
                        break;
                    };
                    let is_virtual = flags & 1 != 0;
                    let offset = signed(flags, width) >> 8;
                    bases.push(Base {
                        name,
                        offset: (!is_virtual).then_some(offset),
                        is_virtual,
                        is_public: flags & 2 != 0,
                        vtable_offset: is_virtual.then_some(offset),
                        vbtable: None,
                    });
                }
                if !valid {
                    continue;
                }
            }
            classes.insert(
                address,
                Class {
                    name,
                    type_info: address,
                    bases,
                    vtables: Vec::new(),
                },
            );
        }
    }
    for section in &image.sections {
        if !section.loaded || section.executable || section.file_offset.is_none() {
            continue;
        }
        let Some(bytes) = image.read_vaddr(section.vaddr, section.size) else {
            continue;
        };
        for (index, chunk) in bytes.chunks_exact(width as usize).enumerate() {
            let info = unsigned(chunk);
            let Some(class) = classes.get_mut(&info) else {
                continue;
            };
            let Some(at) = section.vaddr.checked_add(index as u64 * width) else {
                break;
            };
            let (Some(top_at), Some(point)) = (at.checked_sub(width), at.checked_add(width)) else {
                continue;
            };
            let Some(top) = super::word(image, top_at, width).map(|value| signed(value, width))
            else {
                continue;
            };
            if !(-0x100_0000..=0).contains(&top) {
                continue;
            }
            let methods = super::methods(image, point);
            if methods.is_empty() {
                continue;
            }
            class.vtables.push(Vtable {
                address: point,
                offset: -top,
                construction_displacement: None,
                methods,
            });
        }
    }
    for class in classes.values_mut() {
        for base in &mut class.bases {
            let Some(offset) = base.vtable_offset else {
                continue;
            };
            let mut resolved = None;
            let mut consistent = true;
            for table in &class.vtables {
                if table.offset != 0 {
                    continue;
                }
                let value = table
                    .address
                    .checked_add_signed(offset)
                    .and_then(|at| super::word(image, at, width));
                let Some(value) = value.map(|value| signed(value, width)) else {
                    consistent = false;
                    break;
                };
                if resolved.is_some_and(|known| known != value) {
                    consistent = false;
                    break;
                }
                resolved = Some(value);
            }
            if consistent {
                base.offset = resolved;
            }
        }
    }
    classes.into_values().collect()
}

fn unsigned(bytes: &[u8]) -> u64 {
    let mut word = [0; 8];
    word[..bytes.len()].copy_from_slice(bytes);
    u64::from_le_bytes(word)
}

fn signed(value: u64, width: u64) -> i64 {
    if width == 4 {
        i64::from(value as i32)
    } else {
        value as i64
    }
}
