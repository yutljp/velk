//! Read-only registry keys supplied explicitly in execution options.

use std::collections::BTreeMap;

use crate::emulation::RegistryValue;

use super::{Runner, Stop};

pub(super) struct Key {
    path: String,
    query: bool,
}

const ROOTS: [&str; 5] = [
    "hkey_classes_root",
    "hkey_current_user",
    "hkey_local_machine",
    "hkey_users",
    "hkey_current_config",
];

fn root(handle: u64) -> Option<&'static str> {
    if handle > u64::from(u32::MAX) && handle >> 32 != u64::from(u32::MAX) {
        return None;
    }
    match handle as u32 {
        0x8000_0000 => Some(ROOTS[0]),
        0x8000_0001 => Some(ROOTS[1]),
        0x8000_0002 => Some(ROOTS[2]),
        0x8000_0003 => Some(ROOTS[3]),
        0x8000_0005 => Some(ROOTS[4]),
        _ => None,
    }
}

pub(super) fn contents(
    options: &BTreeMap<String, BTreeMap<String, RegistryValue>>,
) -> Result<BTreeMap<String, BTreeMap<String, RegistryValue>>, String> {
    let mut registry = BTreeMap::new();
    let mut size = 0usize;
    for (path, values) in options {
        let path = path.to_ascii_lowercase();
        let parts: Vec<&str> = path.split('\\').collect();
        if !path.is_ascii()
            || !ROOTS.contains(&parts[0])
            || parts.contains(&"")
            || path.contains('\0')
        {
            return Err(format!("invalid registry key path {path}"));
        }
        size = size.saturating_add(path.len());
        let mut normalized = BTreeMap::new();
        for (name, value) in values {
            if !name.is_ascii() || name.contains('\0') {
                return Err(format!(
                    "registry value name requires ASCII without NUL in {path}"
                ));
            }
            size = size
                .saturating_add(name.len())
                .saturating_add(value.bytes.len());
            if size > super::super::HEAP_SIZE as usize {
                return Err("registry contents exceed 16 MiB".to_owned());
            }
            if normalized
                .insert(name.to_lowercase(), value.clone())
                .is_some()
            {
                return Err(format!(
                    "duplicate case-insensitive registry value in {path}"
                ));
            }
        }
        if size > super::super::HEAP_SIZE as usize {
            return Err("registry contents exceed 16 MiB".to_owned());
        }
        if registry.insert(path, normalized).is_some() {
            return Err("duplicate case-insensitive registry key".to_owned());
        }
    }
    Ok(registry)
}

impl Runner<'_> {
    pub(super) fn windows_registry_api(&mut self, name: &str, args: &[u64]) -> Result<u64, Stop> {
        let predefined = root(args[0]);
        if name == "RegCloseKey" {
            return Ok(
                if predefined.is_some()
                    || self
                        .windows_state_mut()
                        .registry_handles
                        .remove(&args[0])
                        .is_some()
                {
                    0
                } else {
                    6
                },
            );
        }
        let (path, query) = if let Some(path) = predefined {
            (path.to_owned(), true)
        } else if let Some(key) = self.windows_state().registry_handles.get(&args[0]) {
            (key.path.clone(), key.query)
        } else {
            return Ok(6);
        };
        let text = if args[1] == 0 {
            String::new()
        } else {
            match self.windows_string(args[1], name.ends_with('W')) {
                Ok(text) if text.is_ascii() => text.to_ascii_lowercase(),
                Ok(_) => {
                    return Err(Stop::Error(
                        "registry key and value names require ASCII".to_owned(),
                    ));
                }
                Err(stop) => return Err(stop),
            }
        };
        if name.starts_with("RegOpenKeyEx") {
            if args[2] as u32 != 0 || args[4] == 0 {
                return Ok(87);
            }
            if args[3] as u32 & !0x20019 != 0 {
                return Err(Stop::Error(format!(
                    "{name} supports read access in the default registry view only"
                )));
            }
            if text.is_empty() && predefined.is_some() {
                let width = crate::arch::pointer_bytes(self.image.isa) as usize;
                return match self.store_bytes(args[4], &args[0].to_le_bytes()[..width]) {
                    Ok(()) => Ok(0),
                    Err(stop) => Err(stop),
                };
            }
            let path = if text.is_empty() {
                path
            } else {
                format!("{path}\\{text}")
            };
            let exists = ROOTS.contains(&path.as_str())
                || self.windows_state().registry.keys().any(|key| {
                    key == &path
                        || key
                            .strip_prefix(&path)
                            .is_some_and(|suffix| suffix.starts_with('\\'))
                });
            if !exists {
                return Ok(2);
            }
            let handle = self.allocate(1);
            if handle == 0 {
                return Ok(8);
            }
            let width = crate::arch::pointer_bytes(self.image.isa) as usize;
            if let Err(stop) = self.store_bytes(args[4], &handle.to_le_bytes()[..width]) {
                return Err(stop);
            }
            self.windows_state_mut().registry_handles.insert(
                handle,
                Key {
                    path,
                    query: args[3] & 1 != 0,
                },
            );
            return Ok(0);
        }
        if args[2] != 0 || (args[4] != 0 && args[5] == 0) {
            return Ok(87);
        }
        if !query {
            return Ok(5);
        }
        let Some(value) = self
            .windows_state()
            .registry
            .get(&path)
            .and_then(|values| values.get(&text))
            .cloned()
        else {
            return Ok(2);
        };
        if args[4] == 0 && args[5] == 0 {
            if args[3] == 0 {
                return Ok(0);
            }
            return match self.store_bytes(args[3], &value.value_type.to_le_bytes()) {
                Ok(()) => Ok(0),
                Err(stop) => Err(stop),
            };
        }
        let bytes = if name.ends_with('A') && matches!(value.value_type, 1 | 2 | 7) {
            if value.bytes.len() % 2 != 0 {
                return Err(Stop::Error(
                    "ANSI registry query requires an even UTF-16 byte count".to_owned(),
                ));
            }
            let mut bytes = Vec::new();
            for unit in value.bytes.as_chunks::<2>().0 {
                let unit = u16::from_le_bytes([unit[0], unit[1]]);
                if unit > 127 {
                    return Err(Stop::Error(
                        "ANSI registry strings require ASCII".to_owned(),
                    ));
                }
                bytes.push(unit as u8);
            }
            bytes
        } else {
            value.bytes
        };
        let capacity = if args[4] != 0 {
            let capacity = self.machine.load(args[5], 4);
            if let Err(stop) = self.memory_error() {
                return Err(stop);
            }
            capacity
        } else {
            0
        };
        if args[3] != 0
            && let Err(stop) = self.store_bytes(args[3], &value.value_type.to_le_bytes())
        {
            return Err(stop);
        }
        if args[5] != 0
            && let Err(stop) = self.store_bytes(args[5], &(bytes.len() as u32).to_le_bytes())
        {
            return Err(stop);
        }
        if args[4] == 0 {
            return Ok(0);
        }
        if capacity < bytes.len() as u64 {
            return Ok(234);
        }
        match self.store_bytes(args[4], &bytes) {
            Ok(()) => Ok(0),
            Err(stop) => Err(stop),
        }
    }
}
