//! Analysis state that outlives a single script: loaded images and the
//! per-function lift results, keyed so repeated queries skip the work.

use std::collections::HashMap;
use std::time::SystemTime;

use serde_json::{Value, json};

use crate::ir::FunctionIr;
use crate::loader::{Image, Isa};
use crate::refs::Reference;
use crate::{analysis, code, fncard, loader, pass, refs, sigs};

const DEFAULT_BUDGET: u64 = 240;

#[derive(Default)]
pub struct Session {
    binaries: HashMap<String, Binary>,
}

struct Binary {
    modified: SystemTime,
    image: Image,
    callees: HashMap<u64, String>,
    data_ranges: Vec<(u64, u64)>,
    lifted: HashMap<u64, Result<Lifted, String>>,
}

struct Lifted {
    ir: FunctionIr,
    references: Vec<Reference>,
}

impl Session {
    pub fn call(&mut self, op: &str, args: &Value) -> Result<Value, String> {
        if op == "open" {
            return self.open(str_arg(args, "path")?);
        }
        let binary = self
            .binaries
            .get_mut(str_arg(args, "bin")?)
            .ok_or("binary is not open")?;
        match op {
            "sections" => Ok(binary.sections()),
            "functions" => Ok(binary.functions()),
            "buildSignatures" => {
                serde_json::to_value(sigs::build(&binary.image)).map_err(|e| e.to_string())
            }
            "identify" => binary.identify(args),
            _ => binary.function_op(op, args),
        }
    }

    fn open(&mut self, path: &str) -> Result<Value, String> {
        let path = std::fs::canonicalize(path).map_err(|e| format!("{path}: {e}"))?;
        let modified = std::fs::metadata(&path)
            .and_then(|metadata| metadata.modified())
            .map_err(|e| e.to_string())?;
        let id = path.to_string_lossy().into_owned();
        if self
            .binaries
            .get(&id)
            .is_none_or(|b| b.modified != modified)
        {
            let image = loader::load(&path)?;
            let binary = Binary {
                modified,
                callees: code::callee_names(&image),
                data_ranges: code::data_ranges(&image),
                image,
                lifted: HashMap::new(),
            };
            self.binaries.insert(id.clone(), binary);
        }
        let image = &self.binaries[&id].image;
        Ok(json!({
            "id": id,
            "path": id,
            "format": image.format.to_string(),
            "arch": match image.isa {
                Isa::X86_64 => "x86_64",
                Isa::AArch64 => "aarch64",
                Isa::Unsupported => "unsupported",
            },
            "entry": image.entry.map(hex),
        }))
    }
}

impl Binary {
    fn sections(&self) -> Value {
        self.image
            .sections
            .iter()
            .map(|section| {
                json!({
                    "name": section.name,
                    "addr": hex(section.vaddr),
                    "size": section.size,
                    "executable": section.executable,
                })
            })
            .collect()
    }

    fn functions(&self) -> Value {
        self.image
            .functions
            .values()
            .map(|function| {
                json!({
                    "addr": hex(function.addr),
                    "name": function.name,
                    "size": function.size,
                    "nameSource": function.source.iter().map(ToString::to_string).collect::<Vec<_>>(),
                })
            })
            .collect()
    }

    fn identify(&self, args: &Value) -> Result<Value, String> {
        let database: sigs::Database = match (args.get("db"), args.get("path")) {
            (Some(db), _) => serde_json::from_value(db.clone()).map_err(|e| e.to_string())?,
            (None, Some(Value::String(path))) => {
                let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
                serde_json::from_str(&text).map_err(|e| e.to_string())?
            }
            _ => return Err("identify needs a signature database or its path".to_owned()),
        };
        Ok(sigs::identify(&self.image, &database)
            .iter()
            .map(|hit| {
                json!({
                    "addr": hex(hit.addr),
                    "size": hit.size,
                    "current": hit.current,
                    "matched": hit.matched,
                })
            })
            .collect())
    }

    fn function_op(&mut self, op: &str, args: &Value) -> Result<Value, String> {
        let addr = parse_addr(str_arg(args, "addr")?)?;
        let function = self
            .image
            .functions
            .get(&addr)
            .ok_or_else(|| format!("no function at {}", hex(addr)))?;
        if op == "disasm" {
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
                .map_or(usize::MAX, |n| n as usize);
            let len = function.size.unwrap_or(256);
            return Ok(json!(fncard::disassemble(
                &self.image,
                addr,
                len,
                limit,
                false
            )));
        }
        let image = &self.image;
        let lifted = self
            .lifted
            .entry(addr)
            .or_insert_with(|| lift(image, function))
            .as_ref();
        if op == "card" {
            let budget = args
                .get("budget")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_BUDGET);
            let preview = (budget.saturating_sub(96) / 6) as usize;
            let lifted = lifted.ok();
            let strings = lifted.map(|l| strings(&l.references)).unwrap_or_default();
            let card = fncard::build(
                image,
                function,
                preview,
                lifted.map(|l| &l.ir),
                strings.clone(),
                refs::name_hints(&strings),
                lifted.map(|l| l.ir.accesses.clone()).unwrap_or_default(),
                None,
            );
            return serde_json::to_value(card).map_err(|e| e.to_string());
        }
        let Lifted { ir, references } = lifted.map_err(Clone::clone)?;
        match op {
            "decompile" => Ok(json!(code::render(
                &mut ir.clone(),
                references,
                &self.callees,
                self.data_ranges.clone(),
            ))),
            "ir" => Ok(json!(ir.render())),
            "signature" => Ok(json!({
                "return": ir.ret_type,
                "params": ir.params.iter().map(|p| json!({ "name": p.name, "type": p.ty })).collect::<Vec<_>>(),
            })),
            "references" => Ok(references
                .iter()
                .map(|reference| {
                    json!({
                        "addr": hex(reference.addr),
                        "section": reference.section,
                        "text": reference.text,
                        "pointer": reference.pointer.map(hex),
                    })
                })
                .collect()),
            "strings" => Ok(json!(strings(references))),
            "evidence" => Ok(json!(sigs::hash(&sigs::tokens(ir)))),
            other => Err(format!("unknown operation: {other}")),
        }
    }
}

fn lift(image: &Image, function: &loader::Function) -> Result<Lifted, String> {
    let mut ir = analysis::lift(image, function, function.size.unwrap_or(256))?;
    pass::simplify(&mut ir);
    let references = refs::collect(&ir, image);
    Ok(Lifted { ir, references })
}

fn strings(references: &[Reference]) -> Vec<String> {
    references.iter().filter_map(|r| r.text.clone()).collect()
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {key}"))
}

fn hex(value: u64) -> String {
    format!("0x{value:x}")
}

fn parse_addr(text: &str) -> Result<u64, String> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    u64::from_str_radix(digits, 16).map_err(|_| format!("bad address: {text}"))
}
