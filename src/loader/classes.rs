//! Class names, inheritance and virtual tables described by C++ RTTI.

mod itanium;
mod msvc;
mod references;

pub(crate) use itanium::type_name as itanium_type_name;
pub(crate) use msvc::type_name as msvc_type_name;

use serde::Serialize;

use super::{Format, Image, Isa};

/// A class identified by runtime type information.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Class {
    /// Demangled runtime name.
    pub name: String,
    /// Address of the runtime type descriptor.
    #[serde(serialize_with = "crate::addr::serialize")]
    pub type_info: u64,
    /// Direct bases, in runtime descriptor order.
    pub bases: Vec<Base>,
    /// Virtual tables for this class, including secondary address points.
    pub vtables: Vec<Vtable>,
}

/// One direct base relationship. RTTI does not describe data member sizes.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Base {
    /// Runtime name of the base class.
    pub name: String,
    /// Byte offset in a complete object, if fixed or resolved from its table.
    pub offset: Option<i64>,
    /// Whether inheritance is virtual.
    pub is_virtual: bool,
    /// Whether the base is publicly accessible.
    pub is_public: bool,
    /// Itanium vtable displacement used to look up a virtual base offset.
    pub vtable_offset: Option<i64>,
    /// MSVC vbptr offset and vbtable displacement for a virtual base.
    pub vbtable: Option<VirtualBase>,
}

/// MSVC's dynamic virtual base location.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VirtualBase {
    /// Offset of the vbptr in the object.
    pub pointer_offset: i32,
    /// Byte offset of the signed displacement in the vbtable.
    pub entry_offset: i32,
    /// Fixed displacement added after the virtual adjustment.
    pub member_offset: i32,
}

/// A virtual table address point, where the first method pointer resides.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vtable {
    /// Address of the first method pointer.
    #[serde(serialize_with = "crate::addr::serialize")]
    pub address: u64,
    /// Offset of this table's subobject within the complete object.
    pub offset: i64,
    /// MSVC displacement to a construction-time vtordisp field; absent for Itanium.
    pub construction_displacement: Option<u32>,
    /// Methods in slot order, ending at the first unrecognized entry.
    pub methods: Vec<Method>,
}

/// One virtual method entry. Names absent from the file remain unknown.
#[derive(Debug, Clone, Serialize)]
pub struct Method {
    /// Zero-based pointer slot.
    pub slot: u64,
    /// Code address, which may be an adjustment thunk.
    #[serde(serialize_with = "crate::addr::serialize")]
    pub address: u64,
    /// Symbol or debug name, when available.
    pub name: Option<String>,
}

impl Image {
    /// Returns C++ classes supported by validated runtime descriptors.
    pub fn classes(&self) -> &[Class] {
        self.classes.get_or_init(|| {
            if !matches!(self.isa, Isa::X86_64 | Isa::AArch64)
                || self.byte_order() != Some(object::Endianness::Little)
                || self.go
            {
                return Vec::new();
            }
            match self.format {
                Format::Elf | Format::MachO => itanium::read(self),
                Format::Pe => msvc::read(self),
                _ => Vec::new(),
            }
        })
    }
}

pub(super) fn word(image: &Image, address: u64, size: u64) -> Option<u64> {
    if size > 8 {
        return None;
    }
    let Some(section) = image.section_at(address) else {
        return None;
    };
    let Some(end) = address.checked_add(size) else {
        return None;
    };
    if end > section.vaddr.saturating_add(section.size) {
        return None;
    }
    let Some(bytes) = image.read_vaddr(address, size) else {
        return None;
    };
    let mut value = [0; 8];
    value[..bytes.len()].copy_from_slice(bytes);
    Some(u64::from_le_bytes(value))
}

pub(super) fn text(image: &Image, address: u64) -> Option<&str> {
    let Some(section) = image.section_at(address) else {
        return None;
    };
    let size = section
        .vaddr
        .saturating_add(section.size)
        .saturating_sub(address)
        .min(4096);
    let Some(bytes) = image.read_vaddr(address, size) else {
        return None;
    };
    let Some(end) = bytes.iter().position(|byte| *byte == 0) else {
        return None;
    };
    std::str::from_utf8(&bytes[..end]).ok()
}

fn methods(image: &Image, address: u64) -> Vec<Method> {
    let mut methods = Vec::new();
    for slot in 0..4096 {
        let Some(at) = address.checked_add(slot * 8) else {
            break;
        };
        let Some(target) = word(image, at, 8) else {
            break;
        };
        if !image
            .section_at(target)
            .is_some_and(|section| section.executable)
        {
            // Undefined pure virtual entries may still have dynamic relocations.
            if let Some(name) = image.imports.get(&at)
                && matches!(
                    name.trim_start_matches('_'),
                    "cxa_pure_virtual" | "cxa_deleted_virtual" | "purecall"
                )
            {
                methods.push(Method {
                    slot,
                    address: target,
                    name: Some(super::demangle_name(name)),
                });
                continue;
            }
            break;
        }
        methods.push(Method {
            slot,
            address: target,
            name: image
                .functions
                .get(&target)
                .and_then(|function| function.name.clone()),
        });
    }
    methods
}

#[cfg(test)]
mod tests;

pub(super) fn discover(image: &mut Image) {
    if image.relocatable {
        return;
    }
    let mut addresses = std::collections::BTreeSet::new();
    for class in image.classes() {
        for table in &class.vtables {
            for method in &table.methods {
                if !image.functions.contains_key(&method.address)
                    && image
                        .section_at(method.address)
                        .is_some_and(|section| section.executable)
                {
                    addresses.insert(method.address);
                }
            }
        }
    }
    let mut thunks = Vec::new();
    if image.format == Format::Pe && image.isa == Isa::X86_64 {
        for &address in &addresses {
            if let Some(thunk) = msvc::adjustment_thunk(image, address) {
                thunks.push((address, thunk));
            }
        }
    }
    for address in addresses {
        super::upsert(
            &mut image.functions,
            address,
            None,
            None,
            super::NameSource::Rtti,
        );
    }
    for (address, thunk) in thunks {
        super::upsert(
            &mut image.functions,
            thunk.target,
            None,
            None,
            super::NameSource::Rtti,
        );
        if let Some(function) = image.functions.get_mut(&address) {
            function.size = Some(thunk.size);
            function.size_estimated = false;
        }
    }
}
