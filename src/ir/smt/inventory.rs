//! Generated inventory metadata and explicit source review checks.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::ops::Range;

use sha2::Digest;
use syn::spanned::Spanned;
use syn::visit;
use syn::visit::Visit;

#[derive(Default)]
struct RewriteSpans {
    ranges: Vec<Range<usize>>,
}

impl<'ast> Visit<'ast> for RewriteSpans {
    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        self.ranges.push(function.span().byte_range());
        visit::visit_item_fn(self, function);
    }

    fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
        self.ranges.push(function.span().byte_range());
        visit::visit_impl_item_fn(self, function);
    }

    fn visit_trait_item_fn(&mut self, function: &'ast syn::TraitItemFn) {
        if function.default.is_some() {
            self.ranges.push(function.span().byte_range());
        }
        visit::visit_trait_item_fn(self, function);
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        self.ranges.push(arm.span().byte_range());
        visit::visit_arm(self, arm);
    }
}

fn rewrite_spans(source: &str, path: &str) -> RewriteSpans {
    let syntax = syn::parse_file(source)
        .unwrap_or_else(|error| panic!("parse inventory source {path}: {error}"));
    let mut spans = RewriteSpans::default();
    spans.visit_file(&syntax);
    spans
}

fn rewrite_range(source: &str, spans: &RewriteSpans, anchor: &str) -> Range<usize> {
    assert!(!anchor.is_empty(), "inventory anchor must not be empty");
    let locations: Vec<usize> = source
        .match_indices(anchor)
        .map(|(offset, _)| offset)
        .collect();
    assert_eq!(locations.len(), 1, "anchor must be unique: {anchor}");
    let start = locations[0];
    let end = start + anchor.len();
    spans
        .ranges
        .iter()
        .filter(|range| range.start <= start && end <= range.end)
        .min_by_key(|range| range.len())
        .unwrap_or_else(|| panic!("anchor must be inside a function or match arm: {anchor}"))
        .clone()
}

struct Metadata {
    inventory: String,
    digests: String,
    unreviewed: Vec<String>,
}

fn generate(inventory: &str, read: impl Fn(&str) -> String) -> Metadata {
    let mut lines = inventory.lines();
    let header = lines.next().expect("inventory has a header");
    assert_eq!(
        header,
        "site\trewrite\tside_conditions\twidths\tcoverage\tanchor\treviewed_sha256"
    );
    let mut rows: BTreeMap<(String, String), Vec<(String, bool)>> = BTreeMap::new();
    let mut sources = BTreeMap::new();
    let mut digests_by_anchor = BTreeMap::new();
    let mut unreviewed = Vec::new();
    for line in lines {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 7, "inventory rows have seven fields: {line}");
        let (path, _) = fields[0].rsplit_once(':').expect("inventory file and line");
        let (source, spans) = sources.entry(path).or_insert_with(|| {
            let source = read(path);
            let spans = rewrite_spans(&source, path);
            (source, spans)
        });
        let range = rewrite_range(source, spans, fields[5]);
        let digest = format!("{:x}", sha2::Sha256::digest(source[range].as_bytes()));
        let offset = source.find(fields[5]).expect("anchor was found uniquely");
        let location = source[..offset]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        let reviewed = fields[6] == digest;
        digests_by_anchor.insert((path, fields[5]), digest);
        let site = format!("{path}:{location}");
        let row = format!("{site}\t{}", fields[1..].join("\t"));
        rows.entry((site, fields[1].to_owned()))
            .or_default()
            .push((row, reviewed));
    }
    let mut output = format!("{header}\n");
    let mut retained_anchors = BTreeSet::new();
    for ((site, rewrite), mut group) in rows {
        group.sort();
        group.dedup();
        if group.iter().any(|(_, reviewed)| *reviewed) {
            group.retain(|(_, reviewed)| *reviewed);
        }
        if group.len() > 1 {
            unreviewed.push(format!("{site}: {rewrite} (duplicate key; review rows)"));
        }
        for (row, reviewed) in group {
            if !reviewed {
                unreviewed.push(format!("{site}: {rewrite}"));
            }
            let fields: Vec<&str> = row.split('\t').collect();
            let (path, _) = fields[0].rsplit_once(':').expect("generated file and line");
            retained_anchors.insert((path.to_owned(), fields[5].to_owned()));
            writeln!(output, "{row}").expect("write inventory string");
        }
    }
    let mut digests = String::new();
    for ((path, anchor), digest) in digests_by_anchor {
        if !retained_anchors.contains(&(path.to_owned(), anchor.to_owned())) {
            continue;
        }
        writeln!(digests, "{digest}  {path}\t{anchor}").expect("write digest string");
    }
    Metadata {
        inventory: output,
        digests,
        unreviewed,
    }
}

#[test]
fn inventory_matches_the_reviewed_sources() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let inventory_path = root.join("tests/smt_inventory.tsv");
    let digest_path = root.join("tests/smt_sources.sha256");
    let inventory = fs::read_to_string(&inventory_path).expect("read inventory");
    let generated = generate(&inventory, |path| {
        fs::read_to_string(root.join(path)).unwrap_or_else(|error| panic!("read {path}: {error}"))
    });
    if std::env::var_os("VELK_BLESS").is_some_and(|value| value == "1") {
        fs::write(&inventory_path, &generated.inventory).expect("write inventory locations");
        fs::write(&digest_path, &generated.digests).expect("write source digests");
    } else {
        assert_eq!(
            inventory, generated.inventory,
            "inventory rows are stale, unsorted or duplicated; run VELK_BLESS=1 and review the affected rows"
        );
        assert_eq!(
            fs::read_to_string(&digest_path).expect("read source digests"),
            generated.digests,
            "source digest rows are stale, unsorted or duplicated; run VELK_BLESS=1 and review the affected rows"
        );
    }
    assert!(
        generated.unreviewed.is_empty(),
        "review source changes and coverage, then manually update reviewed_sha256:\n{}",
        generated.unreviewed.join("\n")
    );
}

#[test]
fn merged_rows_are_canonicalized_without_approving_changes() {
    let source = "fn rewrite() {}\n";
    let digest = format!("{:x}", sha2::Sha256::digest(b"fn rewrite() {}"));
    let header = "site\trewrite\tside_conditions\twidths\tcoverage\tanchor\treviewed_sha256\n";
    let row = format!("src/example.rs:1\tExample\tNone\t64\topen\tfn rewrite(\t{digest}\n");
    let old = row.replace(&digest, "old").replace(":1\t", ":9\t");
    let input = format!("{header}{old}{row}{row}");
    let generated = generate(&input, |_| source.to_owned());
    assert_eq!(generated.inventory, format!("{header}{row}"));
    assert!(generated.unreviewed.is_empty());

    let unresolved = format!("{header}{old}{}", old.replace("old", "other"));
    let generated = generate(&unresolved, |_| source.to_owned());
    assert_eq!(generated.inventory.lines().count(), 3);
    assert!(
        generated
            .unreviewed
            .iter()
            .any(|row| row.contains("duplicate key"))
    );
    assert_eq!(generated.unreviewed.len(), 3);

    let different_coverage = row.replace("\topen\t", "\tpartial\t");
    let generated = generate(&format!("{header}{row}{different_coverage}"), |_| {
        source.to_owned()
    });
    assert_eq!(generated.inventory.lines().count(), 3);
    assert!(
        generated
            .unreviewed
            .iter()
            .any(|row| row.contains("duplicate key"))
    );

    let source = "fn rewrite() {} fn other() {}";
    let other = old.replace("fn rewrite(", "fn other(");
    let generated = generate(&format!("{header}{row}{other}"), |_| source.to_owned());
    assert_eq!(generated.inventory, format!("{header}{row}"));
    assert_eq!(generated.digests.lines().count(), 1);
    assert!(generated.digests.contains("fn rewrite("));
}

#[test]
fn regeneration_preserves_review_and_detects_source_changes() {
    let source = "fn rewrite() {}\n";
    let digest = format!("{:x}", sha2::Sha256::digest(b"fn rewrite() {}"));
    let inventory = format!(
        "site\trewrite\tside_conditions\twidths\tcoverage\tanchor\treviewed_sha256\n\
         src/example.rs:99\tExample\tNone\t64\topen\tfn rewrite(\t{digest}\n"
    );
    let generated = generate(&inventory, |_| source.to_owned());
    assert!(generated.unreviewed.is_empty());
    assert_eq!(generated.inventory, inventory.replace(":99\t", ":1\t"));
    assert_eq!(
        generated.digests,
        format!("{digest}  src/example.rs\tfn rewrite(\n")
    );
    let changed = generate(&generated.inventory, |_| {
        "\nfn rewrite() { changed(); }\n".to_owned()
    });
    assert_eq!(changed.unreviewed, ["src/example.rs:2: Example"]);
    assert_eq!(changed.inventory, inventory.replace(":99\t", ":2\t"));
    assert_ne!(changed.digests, generated.digests);
    let regenerated = generate(&changed.inventory, |_| {
        "\nfn rewrite() { changed(); }\n".to_owned()
    });
    assert_eq!(regenerated.unreviewed, changed.unreviewed);
    assert_eq!(regenerated.inventory, changed.inventory);
}

#[test]
fn unrelated_edits_and_moves_preserve_review() {
    let source = "fn other() { before(); }\nfn rewrite() { original(); }\n";
    let digest = format!(
        "{:x}",
        sha2::Sha256::digest(b"fn rewrite() { original(); }")
    );
    let inventory = format!(
        "site\trewrite\tside_conditions\twidths\tcoverage\tanchor\treviewed_sha256\n\
         src/example.rs:2\tExample\tNone\t64\topen\tfn rewrite(\t{digest}\n"
    );
    let generated = generate(&inventory, |_| source.to_owned());
    let unrelated = generate(&inventory, |_| source.replace("before()", "after()"));
    assert!(unrelated.unreviewed.is_empty());
    assert_eq!(generated.inventory, unrelated.inventory);
    assert_eq!(generated.digests, unrelated.digests);

    let moved_source = "fn rewrite() { original(); }\nfn other() { before(); }\n";
    let moved = generate(&inventory, |_| moved_source.to_owned());
    assert!(moved.unreviewed.is_empty());
    assert_eq!(moved.inventory, inventory.replace(":2\t", ":1\t"));
    assert_eq!(generated.digests, moved.digests);
    let regenerated = generate(&moved.inventory, |_| moved_source.to_owned());
    assert!(regenerated.unreviewed.is_empty());
    assert_eq!(regenerated.inventory, moved.inventory);
    assert_eq!(regenerated.digests, moved.digests);
}

#[test]
fn ranges_follow_rust_syntax() {
    let source = r####"
// Unicode before the function: 日本語.
#[inline]
fn rewrite<T: Trait<{ 1 + 2 }>>(value: T) {
    let text = r###" } => { "###;
    let character = '}';
    /* } /* { */ } */
    match value {
        First | Second if guard() => {
            original(); // }
        },
        Third => other(),
    }
}
fn unrelated() {}
"####;
    let spans = rewrite_spans(source, "example.rs");
    let function = &source[rewrite_range(source, &spans, "fn rewrite<")];
    assert!(function.starts_with("#[inline]\nfn rewrite<"));
    assert!(function.ends_with("\n}"));
    assert!(!function.contains("fn unrelated"));
    let arm = &source[rewrite_range(source, &spans, "original();")];
    assert_eq!(
        arm,
        "First | Second if guard() => {\n            original(); // }\n        },"
    );
    assert_eq!(
        arm,
        &source[rewrite_range(source, &spans, "First | Second")]
    );
    assert_eq!(
        &source[rewrite_range(source, &spans, "Third =>")],
        "Third => other(),"
    );
}

#[test]
fn match_arm_review_covers_pattern_guard_and_body() {
    let arm = "First if guard() => original(),";
    let source = format!("fn lower() {{ match value {{ {arm} Other => other(), }} }}");
    let digest = format!("{:x}", sha2::Sha256::digest(arm.as_bytes()));
    let inventory = format!(
        "site\trewrite\tside_conditions\twidths\tcoverage\tanchor\treviewed_sha256\n\
         src/example.rs:1\tExample\tNone\t64\topen\toriginal()\t{digest}\n"
    );
    assert!(
        generate(&inventory, |_| source.to_owned())
            .unreviewed
            .is_empty()
    );
    let unrelated = generate(&inventory, |_| source.replace("other()", "changed()"));
    assert!(unrelated.unreviewed.is_empty());
    for (before, after) in [
        ("First", "Second"),
        ("guard()", "!guard()"),
        ("original()", "original() + 1"),
    ] {
        let changed = generate(&inventory, |_| source.replace(before, after));
        assert_eq!(changed.unreviewed, ["src/example.rs:1: Example"]);
    }
}

#[test]
fn method_and_nested_arm_ranges_are_selected() {
    let source = r#"
trait Example {
    fn default_method() { original(); }
}
impl Example for Value {
    fn method() {
        match outer {
            Outer => match inner {
                Inner => nested(),
            },
        }
    }
}
"#;
    let spans = rewrite_spans(source, "example.rs");
    for method in ["default_method", "method"] {
        let anchor = format!("fn {method}(");
        let selected = &source[rewrite_range(source, &spans, &anchor)];
        assert!(selected.starts_with(&anchor));
        assert!(selected.ends_with('}'));
    }
    assert_eq!(
        &source[rewrite_range(source, &spans, "nested()")],
        "Inner => nested(),"
    );
}

#[test]
fn function_review_includes_attributes_signature_and_comments() {
    let source = "#[inline]\nfn rewrite(value: u64) { /* original */ consume(value); }";
    let digest = format!("{:x}", sha2::Sha256::digest(source.as_bytes()));
    let inventory = format!(
        "site\trewrite\tside_conditions\twidths\tcoverage\tanchor\treviewed_sha256\n\
         src/example.rs:2\tExample\tNone\t64\topen\tfn rewrite(\t{digest}\n"
    );
    assert!(
        generate(&inventory, |_| source.to_owned())
            .unreviewed
            .is_empty()
    );
    for (before, after) in [
        ("#[inline]", "#[cold]"),
        ("u64", "u32"),
        ("original", "changed"),
        ("consume(value)", "consume( value )"),
    ] {
        let changed = generate(&inventory, |_| source.replace(before, after));
        assert_eq!(changed.unreviewed, ["src/example.rs:2: Example"]);
    }
}

#[test]
#[should_panic(expected = "anchor must be unique")]
fn duplicate_anchors_are_rejected() {
    let source = "fn rewrite() { original(); original(); }";
    rewrite_range(source, &rewrite_spans(source, "example.rs"), "original()");
}

#[test]
#[should_panic(expected = "anchor must be inside a function or match arm")]
fn anchors_outside_rewrites_are_rejected() {
    let source = "const VALUE: u64 = 1;";
    rewrite_range(source, &rewrite_spans(source, "example.rs"), "VALUE");
}
