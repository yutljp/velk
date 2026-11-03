//! Every change the decompiling pipeline makes to a function's IR goes
//! through `passes::checked`, so the rewrite validation sees it.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use syn::visit::Visit;

/// The functions whose bodies run the pipeline.
const PIPELINE: [(&str, Option<&str>); 2] = [
    ("src/analysis/optimization.rs", None),
    ("src/passes/mod.rs", Some("optimize")),
];

fn name(function: &syn::ItemFn) -> &syn::Ident {
    let syn::ItemFn {
        sig: syn::Signature { ident, .. },
        ..
    } = function;
    ident
}

/// Each function of the crate, as `module::function` with the module named
/// by its file, and whether its body runs its work through `checked`.
fn functions(root: &Path) -> BTreeMap<String, bool> {
    struct Bodies<'a> {
        module: &'a str,
        found: &'a mut BTreeMap<String, bool>,
    }
    impl<'ast> Visit<'ast> for Bodies<'_> {
        fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
            let mut calls = Calls::default();
            calls.visit_block(&function.block);
            let name = format!("{}::{}", self.module, name(function));
            *self.found.entry(name).or_insert(true) &= calls.checked;
            syn::visit::visit_item_fn(self, function);
        }
    }
    #[derive(Default)]
    struct Calls {
        checked: bool,
    }
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if last(&call.func).is_some_and(|name| name.starts_with("checked")) {
                self.checked = true;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut found = BTreeMap::new();
    let mut work = vec![root.join("src")];
    while let Some(directory) = work.pop() {
        for entry in fs::read_dir(&directory).expect("read source directory") {
            let path = entry.expect("source entry").path();
            if path.is_dir() {
                work.push(path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            let module = match path.file_stem().and_then(|stem| stem.to_str()) {
                Some("mod") => path
                    .parent()
                    .and_then(|parent| parent.file_name())
                    .and_then(|name| name.to_str())
                    .expect("module directory")
                    .to_owned(),
                Some(stem) => stem.to_owned(),
                None => continue,
            };
            let source = fs::read_to_string(&path).expect("read source");
            let syntax = syn::parse_file(&source).expect("parse source");
            Bodies {
                module: &module,
                found: &mut found,
            }
            .visit_file(&syntax);
        }
    }
    found
}

/// The last segment of a called path.
fn last(func: &syn::Expr) -> Option<String> {
    match func {
        syn::Expr::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

/// `module::function` of a called path, the module being the segment before
/// the function's, or `here` for a bare name.
fn callee(func: &syn::Expr, here: &str) -> Option<String> {
    let syn::Expr::Path(path) = func else {
        return None;
    };
    let segments: Vec<String> = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    match segments.as_slice() {
        [function] => Some(format!("{here}::{function}")),
        [.., module, function] => Some(format!("{module}::{function}")),
        [] => None,
    }
}

/// Whether `expr` hands the function's IR over to be changed: `&mut ir`, or
/// `ir` where it is a mutable reference already.
fn hands_over(expr: &syn::Expr) -> bool {
    let named =
        |expr: &syn::Expr| matches!(expr, syn::Expr::Path(path) if path.path.is_ident("ir"));
    match expr {
        syn::Expr::Reference(reference) => reference.mutability.is_some() && named(&reference.expr),
        other => named(other),
    }
}

/// Whether `name`, called as `module::function`, runs through `checked`:
/// the function of that module, or, for a name a module re-exports, every
/// function of that name.
fn runs_checked(functions: &BTreeMap<String, bool>, name: &str) -> bool {
    if let Some(checked) = functions.get(name) {
        return *checked;
    }
    let function = name.rsplit("::").next().unwrap_or(name);
    let mut same = functions
        .iter()
        .filter(|(other, _)| other.rsplit("::").next() == Some(function))
        .peekable();
    same.peek().is_some() && same.all(|(_, checked)| *checked)
}

/// Methods that change the vector they are called on.
const CHANGING: [&str; 12] = [
    "iter_mut", "retain", "push", "insert", "remove", "clear", "swap", "sort", "sort_by", "drain",
    "truncate", "extend",
];

/// Whether `expr` is `ir.blocks`, or a part of it.
fn blocks(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Field(field) => {
            matches!(&field.member, syn::Member::Named(name) if name == "blocks")
                && matches!(field.base.as_ref(), syn::Expr::Path(path) if path.path.is_ident("ir"))
                || blocks(&field.base)
        }
        syn::Expr::Index(index) => blocks(&index.expr),
        syn::Expr::MethodCall(call) => blocks(&call.receiver),
        _ => false,
    }
}

struct Pipeline<'a> {
    module: &'a str,
    only: Option<&'a str>,
    inside: bool,
    functions: &'a BTreeMap<String, bool>,
    local: &'a BTreeSet<String>,
    unchecked: Vec<String>,
}
impl<'ast> Visit<'ast> for Pipeline<'_> {
    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        let inside = self.only.is_none_or(|only| name(function) == only);
        let outer = std::mem::replace(&mut self.inside, inside);
        syn::visit::visit_item_fn(self, function);
        self.inside = outer;
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        // What a checked call runs is the checked change itself.
        if last(&call.func).is_some_and(|name| name.starts_with("checked")) {
            return;
        }
        if self.inside && call.args.iter().any(hands_over) {
            let name = callee(&call.func, self.module).unwrap_or_default();
            if !runs_checked(self.functions, &name) && !self.local.contains(&name) {
                self.unchecked.push(name);
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if self.inside
            && CHANGING.contains(&call.method.to_string().as_str())
            && blocks(&call.receiver)
        {
            self.unchecked
                .push(format!("ir.blocks...{}()", call.method));
        }
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_expr_assign(&mut self, assign: &'ast syn::ExprAssign) {
        if self.inside && blocks(&assign.left) {
            self.unchecked.push("an assignment to ir.blocks".to_owned());
        }
        syn::visit::visit_expr_assign(self, assign);
    }
    fn visit_expr_reference(&mut self, reference: &'ast syn::ExprReference) {
        if self.inside && reference.mutability.is_some() && blocks(&reference.expr) {
            self.unchecked.push("&mut ir.blocks".to_owned());
        }
        syn::visit::visit_expr_reference(self, reference);
    }
}

/// The changes `syntax`, the pipeline file of `module`, makes to the IR
/// outside `checked`, in its function `only` or in all of them.
fn unchecked_steps(
    syntax: &syn::File,
    module: &str,
    only: Option<&str>,
    functions: &BTreeMap<String, bool>,
    local: &BTreeSet<String>,
) -> Vec<String> {
    let mut pipeline = Pipeline {
        module,
        only,
        inside: false,
        functions,
        local,
        unchecked: Vec::new(),
    };
    pipeline.visit_file(syntax);
    pipeline.unchecked
}

#[test]
fn unchecked_steps_are_found() {
    let syntax = syn::parse_file(
        "fn run(ir: &mut FunctionIr) {
            tidy(ir);
            crate::passes::checked(\"tidy\", ir, |ir| tidy(ir));
            passes::checked_pass(ir);
            ir.blocks.retain(|_| true);
            for block in &mut ir.blocks {}
            let _ = passes::reads(&ir);
        }",
    )
    .expect("parse");
    let functions: BTreeMap<String, bool> = [
        ("pipeline::tidy".to_owned(), false),
        ("passes::checked_pass".to_owned(), true),
        ("passes::reads".to_owned(), false),
    ]
    .into();
    assert_eq!(
        unchecked_steps(&syntax, "pipeline", None, &functions, &BTreeSet::new()),
        ["pipeline::tidy", "ir.blocks...retain()", "&mut ir.blocks"]
    );
}

#[test]
fn the_pipeline_changes_the_ir_only_through_checked_passes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let functions = functions(root);
    // The pipeline's own functions are checked statement by statement.
    let mut local = BTreeSet::new();
    let mut syntaxes = Vec::new();
    for (file, only) in PIPELINE {
        let source = fs::read_to_string(root.join(file)).expect("read pipeline source");
        let syntax = syn::parse_file(&source).expect("parse pipeline source");
        let module = Path::new(file)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(|stem| if stem == "mod" { "passes" } else { stem })
            .expect("pipeline module");
        for item in &syntax.items {
            if let syn::Item::Fn(function) = item
                && only.is_none_or(|only| name(function) == only)
            {
                local.insert(format!("{module}::{}", name(function)));
            }
        }
        syntaxes.push((file, module, only, syntax));
    }
    let mut unchecked = Vec::new();
    for (file, module, only, syntax) in &syntaxes {
        unchecked.extend(
            unchecked_steps(syntax, module, *only, &functions, &local)
                .into_iter()
                .map(|name| format!("{file}: {name}")),
        );
    }
    assert!(
        unchecked.is_empty(),
        "pipeline steps that change the IR outside passes::checked:\n{}",
        unchecked.join("\n")
    );
}
