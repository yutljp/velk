//! Persistent, binary-bound analysis annotations.
mod apply;
pub use apply::origins;
pub(crate) use apply::scalar_parameters;
pub mod cli;
mod storage;
mod types;

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub use storage::{load, path, update};
pub(crate) use storage::{load_at, update_cached};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// A stable annotation selector independent of printed names.
pub enum Target {
    Function {
        #[serde(with = "address")]
        address: u64,
    },
    Parameter {
        #[serde(with = "address")]
        function: u64,
        storage: Storage,
    },
    Local {
        #[serde(with = "address")]
        function: u64,
        storage: Storage,
    },
    Global {
        #[serde(with = "address")]
        address: u64,
    },
    Declaration {
        name: String,
    },
    Comment {
        #[serde(with = "address")]
        address: u64,
    },
    Classification {
        #[serde(with = "address")]
        address: u64,
    },
    Signature {
        #[serde(with = "address")]
        function: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Machine storage or a split definition origin.
pub enum Storage {
    Register {
        register: u16,
    },
    Stack {
        offset: i64,
    },
    /// A split value identified by its machine register and first definition.
    Definition {
        register: u16,
        #[serde(with = "address")]
        block: u64,
        statement: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// User-provided metadata for one target.
pub struct Annotation {
    pub target: Target,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub c_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// A versioned document bound to the binary SHA-256.
pub struct Project {
    pub version: u32,
    pub binary_sha256: String,
    /// Headerless mapping retained for reopening the annotated file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<crate::loader::RawOptions>,
    pub annotations: Vec<Annotation>,
}

#[derive(Debug, thiserror::Error, Serialize)]
#[error("{}", serde_json::json!({"code": code, "message": message}))]
/// A machine-readable project failure.
pub struct ProjectError {
    pub code: String,
    pub message: String,
}

pub(crate) fn error(code: &str, message: impl Into<String>) -> Error {
    Error::Project(ProjectError {
        code: code.to_owned(),
        message: message.into(),
    })
}

pub(super) fn io(path: &Path, cause: impl std::fmt::Display) -> Error {
    error("project_io", format!("{}: {cause}", path.display()))
}

impl Project {
    pub(crate) fn set_raw_mapping(
        &mut self,
        raw: Option<&crate::loader::RawOptions>,
    ) -> Result<()> {
        let Some(raw) = raw else {
            return Ok(());
        };
        if self.raw.as_ref().is_some_and(|current| current != raw) {
            return Err(error(
                "invalid_mapping",
                "project uses a different raw mapping",
            ));
        }
        self.raw = Some(raw.clone());
        Ok(())
    }

    /// Returns the annotation for a target, if present.
    #[must_use]
    pub fn get(&self, target: &Target) -> Option<&Annotation> {
        self.annotations
            .iter()
            .find(|entry| &entry.target == target)
    }

    /// Replaces one annotation. Validation of the entire transaction happens before writing.
    pub fn set(&mut self, annotation: Annotation) {
        if let Some(existing) = self
            .annotations
            .iter_mut()
            .find(|entry| entry.target == annotation.target)
        {
            *existing = annotation;
        } else {
            self.annotations.push(annotation);
        }
    }

    /// Removes a target and reports whether it existed.
    pub fn remove(&mut self, target: &Target) -> bool {
        let count = self.annotations.len();
        self.annotations.retain(|entry| &entry.target != target);
        count != self.annotations.len()
    }

    pub(super) fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(error(
                "project_version",
                format!("unsupported project version {}", self.version),
            ));
        }
        for (index, entry) in self.annotations.iter().enumerate() {
            if self.annotations[..index]
                .iter()
                .any(|other| other.target == entry.target)
            {
                return Err(error(
                    "duplicate_target",
                    format!("duplicate target {:?}", entry.target),
                ));
            }
            if let Some(name) = &entry.name
                && !types::identifier(name)
            {
                return Err(error(
                    "invalid_identifier",
                    format!("invalid C identifier: {name}"),
                ));
            }
            let valid = match &entry.target {
                Target::Function { .. } => {
                    entry.name.is_some() && entry.c_type.is_none() && entry.text.is_none()
                }
                Target::Parameter { .. } | Target::Local { .. } | Target::Global { .. } => {
                    (entry.name.is_some() || entry.c_type.is_some()) && entry.text.is_none()
                }
                Target::Comment { .. } => {
                    entry.text.is_some() && entry.name.is_none() && entry.c_type.is_none()
                }
                Target::Declaration { .. } | Target::Signature { .. } => {
                    entry.text.is_some() && entry.name.is_none() && entry.c_type.is_none()
                }
                Target::Classification { .. } => {
                    matches!(entry.text.as_deref(), Some("code" | "data"))
                        && entry.name.is_none()
                        && entry.c_type.is_none()
                }
            };
            if !valid {
                return Err(error(
                    "invalid_annotation",
                    format!("invalid fields for {:?}", entry.target),
                ));
            }
        }
        match types::Types::new(self) {
            Ok(types) => {
                for entry in &self.annotations {
                    if let Some(ty) = &entry.c_type
                        && let Err(cause) = types.parse(ty)
                    {
                        return Err(cause);
                    }
                    if let Target::Signature { .. } = entry.target
                        && let Err(cause) =
                            types.signature(entry.text.as_deref().unwrap_or_default())
                    {
                        return Err(cause);
                    }
                }
                Ok(())
            }
            Err(cause) => Err(cause),
        }
    }
}

mod address {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        crate::addr::serialize(value, serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Address {
            Text(String),
            Number(u64),
        }
        match Address::deserialize(deserializer) {
            Ok(Address::Number(value)) => Ok(value),
            Ok(Address::Text(text)) => match crate::addr::parse(&text) {
                Some(value) => Ok(value),
                None => Err(serde::de::Error::custom(
                    "expected a decimal or 0x-prefixed address",
                )),
            },
            Err(cause) => Err(cause),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm32_names_apply_but_64_bit_type_layouts_are_rejected() {
        let mut ir = crate::ir::FunctionIr::single_block(crate::loader::Isa::Arm32, Vec::new());
        let mut symbols = crate::render::Symbols::default();
        let mut project = Project {
            version: 1,
            binary_sha256: String::new(),
            raw: None,
            annotations: Vec::new(),
        };
        project.set(Annotation {
            target: Target::Function { address: ir.addr },
            name: Some("calculate".to_owned()),
            c_type: None,
            text: None,
        });
        project.apply(&mut ir, &mut symbols).unwrap();
        assert!(crate::render::render(&ir, &[], &symbols, &[]).contains("calculate("));
        project.set(Annotation {
            target: Target::Global { address: 0x1234 },
            name: None,
            c_type: Some("int32_t *".to_owned()),
            text: None,
        });
        let error = project.apply(&mut ir, &mut symbols).unwrap_err();
        assert!(error.to_string().contains("unsupported_type"));
    }

    #[test]
    fn naming_an_unnamed_function_keeps_numeric_constants_numeric() {
        let ir = crate::ir::FunctionIr::single_block(
            crate::loader::Isa::X86_64,
            vec![crate::ir::Stmt::Ret {
                value: crate::ir::Expr::Const(0x1234),
            }],
        );
        let mut symbols = crate::render::Symbols::default();
        let expected = crate::render::render(&ir, &[], &symbols, &[]);
        let mut annotated = ir;
        let mut project = Project {
            version: 1,
            binary_sha256: String::new(),
            raw: None,
            annotations: Vec::new(),
        };
        project.set(Annotation {
            target: Target::Function { address: 0x1234 },
            name: Some("helper".to_owned()),
            c_type: None,
            text: None,
        });
        project.apply(&mut annotated, &mut symbols).unwrap();
        assert_eq!(
            crate::render::render(&annotated, &[], &symbols, &[]),
            expected
        );
    }
    #[test]
    fn declared_layouts_cannot_be_hidden_by_inferred_layouts() {
        let mut ir = crate::ir::FunctionIr::single_block(crate::loader::Isa::X86_64, Vec::new());
        ir.structures.push(crate::ir::Structure {
            name: "record".to_owned(),
            fields: vec![(0, crate::ir::CType::I32)],
            size: Some(4),
            elements: vec![0],
        });
        let mut project = Project {
            version: 1,
            binary_sha256: String::new(),
            raw: None,
            annotations: Vec::new(),
        };
        project.set(Annotation {
            target: Target::Declaration {
                name: "struct record".to_owned(),
            },
            name: None,
            c_type: None,
            text: Some("struct record { int32_t value; };".to_owned()),
        });
        let error = project
            .apply(&mut ir, &mut crate::render::Symbols::default())
            .unwrap_err();
        assert!(error.to_string().contains("name_collision"));
    }
}
