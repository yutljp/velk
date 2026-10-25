//! Known library effects used by rendering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Allocation {
    Fresh,
    Reallocated,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SizeRule {
    Argument(usize),
    Product(usize, usize),
    Unknown,
}
pub(crate) struct Buffer {
    pub(crate) arguments: &'static [usize],
    pub(crate) size: usize,
}
pub(crate) struct Naming {
    pub(crate) parameters: &'static [&'static str],
    pub(crate) result: Option<&'static str>,
}
pub(crate) struct Effects {
    pub(crate) buffer: Option<Buffer>,
    pub(crate) allocation: Option<Allocation>,
    pub(crate) size: SizeRule,
    pub(crate) naming: Option<Naming>,
}
pub(crate) fn lookup(name: &str) -> Option<&'static Effects> {
    EFFECTS
        .iter()
        .find_map(|(symbol, effects)| (*symbol == name).then_some(effects))
}
const EFFECTS: &[(&str, Effects)] = &[
    (
        "strlen",
        Effects {
            buffer: None,
            allocation: None,
            size: SizeRule::Argument(0),
            naming: Some(Naming {
                parameters: &["s"],
                result: Some("len"),
            }),
        },
    ),
    (
        "strnlen",
        Effects {
            buffer: None,
            allocation: None,
            size: SizeRule::Argument(0),
            naming: Some(Naming {
                parameters: &["s", "n"],
                result: Some("len"),
            }),
        },
    ),
    (
        "memcpy",
        Effects {
            buffer: Some(Buffer {
                arguments: &[0, 1],
                size: 2,
            }),
            allocation: None,
            size: SizeRule::Argument(0),
            naming: Some(Naming {
                parameters: &["dst", "src", "n"],
                result: None,
            }),
        },
    ),
    (
        "memmove",
        Effects {
            buffer: Some(Buffer {
                arguments: &[0, 1],
                size: 2,
            }),
            allocation: None,
            size: SizeRule::Argument(0),
            naming: Some(Naming {
                parameters: &["dst", "src", "n"],
                result: None,
            }),
        },
    ),
    (
        "memset",
        Effects {
            buffer: Some(Buffer {
                arguments: &[0],
                size: 2,
            }),
            allocation: None,
            size: SizeRule::Argument(0),
            naming: Some(Naming {
                parameters: &["dst", "c", "n"],
                result: None,
            }),
        },
    ),
    (
        "strcmp",
        Effects {
            buffer: None,
            allocation: None,
            size: SizeRule::Argument(0),
            naming: Some(Naming {
                parameters: &["s1", "s2"],
                result: None,
            }),
        },
    ),
    (
        "strncmp",
        Effects {
            buffer: None,
            allocation: None,
            size: SizeRule::Argument(0),
            naming: Some(Naming {
                parameters: &["s1", "s2", "n"],
                result: None,
            }),
        },
    ),
    (
        "malloc",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Fresh),
            size: SizeRule::Argument(0),
            naming: Some(Naming {
                parameters: &["size"],
                result: Some("p"),
            }),
        },
    ),
    (
        "calloc",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Fresh),
            size: SizeRule::Product(0, 1),
            naming: Some(Naming {
                parameters: &["n", "size"],
                result: Some("buf"),
            }),
        },
    ),
    (
        "realloc",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Reallocated),
            size: SizeRule::Argument(1),
            naming: Some(Naming {
                parameters: &["ptr", "size"],
                result: Some("buf"),
            }),
        },
    ),
    (
        "free",
        Effects {
            buffer: None,
            allocation: None,
            size: SizeRule::Argument(0),
            naming: Some(Naming {
                parameters: &["ptr"],
                result: None,
            }),
        },
    ),
    (
        "open",
        Effects {
            buffer: None,
            allocation: None,
            size: SizeRule::Argument(0),
            naming: Some(Naming {
                parameters: &["path", "flags"],
                result: Some("fd"),
            }),
        },
    ),
    (
        "read",
        Effects {
            buffer: None,
            allocation: None,
            size: SizeRule::Argument(0),
            naming: Some(Naming {
                parameters: &["fd", "buf", "n"],
                result: Some("n"),
            }),
        },
    ),
    (
        "write",
        Effects {
            buffer: None,
            allocation: None,
            size: SizeRule::Argument(0),
            naming: Some(Naming {
                parameters: &["fd", "buf", "n"],
                result: Some("n"),
            }),
        },
    ),
    (
        "memset_pattern16",
        Effects {
            buffer: Some(Buffer {
                arguments: &[0],
                size: 2,
            }),
            allocation: None,
            size: SizeRule::Argument(0),
            naming: None,
        },
    ),
    (
        "memset_pattern8",
        Effects {
            buffer: Some(Buffer {
                arguments: &[0],
                size: 2,
            }),
            allocation: None,
            size: SizeRule::Argument(0),
            naming: None,
        },
    ),
    (
        "memset_pattern4",
        Effects {
            buffer: Some(Buffer {
                arguments: &[0],
                size: 2,
            }),
            allocation: None,
            size: SizeRule::Argument(0),
            naming: None,
        },
    ),
    (
        "rust_alloc",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Fresh),
            size: SizeRule::Argument(0),
            naming: None,
        },
    ),
    (
        "rust_alloc_zeroed",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Fresh),
            size: SizeRule::Argument(0),
            naming: None,
        },
    ),
    (
        "rdl_alloc",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Fresh),
            size: SizeRule::Argument(0),
            naming: None,
        },
    ),
    (
        "rdl_alloc_zeroed",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Fresh),
            size: SizeRule::Argument(0),
            naming: None,
        },
    ),
    (
        "runtime.mallocgc",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Fresh),
            size: SizeRule::Argument(0),
            naming: None,
        },
    ),
    (
        "runtime.newobject",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Fresh),
            size: SizeRule::Unknown,
            naming: None,
        },
    ),
    (
        "Znwm",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Fresh),
            size: SizeRule::Argument(0),
            naming: None,
        },
    ),
    (
        "Znam",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Fresh),
            size: SizeRule::Argument(0),
            naming: None,
        },
    ),
    (
        "Znwj",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Fresh),
            size: SizeRule::Argument(0),
            naming: None,
        },
    ),
    (
        "Znaj",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Fresh),
            size: SizeRule::Argument(0),
            naming: None,
        },
    ),
    (
        "operator new(unsigned long)",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Fresh),
            size: SizeRule::Argument(0),
            naming: None,
        },
    ),
    (
        "operator new[](unsigned long)",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Fresh),
            size: SizeRule::Argument(0),
            naming: None,
        },
    ),
    (
        "operator new(unsigned int)",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Fresh),
            size: SizeRule::Argument(0),
            naming: None,
        },
    ),
    (
        "operator new[](unsigned int)",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Fresh),
            size: SizeRule::Argument(0),
            naming: None,
        },
    ),
    (
        "rust_realloc",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Reallocated),
            size: SizeRule::Argument(3),
            naming: None,
        },
    ),
    (
        "rdl_realloc",
        Effects {
            buffer: None,
            allocation: Some(Allocation::Reallocated),
            size: SizeRule::Argument(3),
            naming: None,
        },
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_positions_and_naming_remain_distinct() {
        for name in ["memcpy", "memmove"] {
            let effects = lookup(name).unwrap();
            let buffer = effects.buffer.as_ref().unwrap();
            assert_eq!(buffer.arguments, &[0, 1]);
            assert_eq!(buffer.size, 2);
            let naming = effects.naming.as_ref().unwrap();
            assert_eq!(naming.parameters, &["dst", "src", "n"]);
            assert_eq!(naming.result, None);
        }
        for name in [
            "memset",
            "memset_pattern4",
            "memset_pattern8",
            "memset_pattern16",
        ] {
            let effects = lookup(name).unwrap();
            let buffer = effects.buffer.as_ref().unwrap();
            assert_eq!(buffer.arguments, &[0]);
            assert_eq!(buffer.size, 2);
            assert_eq!(effects.naming.is_some(), name == "memset");
        }
        for name in ["unknown", "_malloc", "__rustc::__rust_alloc"] {
            assert!(lookup(name).is_none());
        }
        let mut names = std::collections::HashSet::new();
        for (name, _) in EFFECTS {
            assert!(names.insert(name));
        }
    }
}
