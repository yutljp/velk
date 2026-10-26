//! Generated inventory metadata and explicit source review checks.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;

use sha2::Digest;

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
    let mut output = format!("{header}\n");
    let mut sources = BTreeMap::new();
    let mut unreviewed = Vec::new();
    for line in lines {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 7, "inventory rows have seven fields: {line}");
        let (path, _) = fields[0].rsplit_once(':').expect("inventory file and line");
        let (source, digest) = sources.entry(path).or_insert_with(|| {
            let source = read(path);
            let digest = format!("{:x}", sha2::Sha256::digest(source.as_bytes()));
            (source, digest)
        });
        let locations: Vec<usize> = source
            .lines()
            .enumerate()
            .filter_map(|(index, line)| line.contains(fields[5]).then_some(index + 1))
            .collect();
        assert_eq!(locations.len(), 1, "anchor must be unique: {line}");
        if fields[6] != digest {
            unreviewed.push(format!("{path}: {}", fields[1]));
        }
        writeln!(
            output,
            "{path}:{}\t{}",
            locations[0],
            fields[1..].join("\t")
        )
        .expect("write inventory string");
    }
    let mut digests = String::new();
    for (path, (_, digest)) in sources {
        writeln!(digests, "{digest}  {path}").expect("write digest string");
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
        assert_eq!(inventory, generated.inventory, "bless inventory locations");
        assert_eq!(
            fs::read_to_string(&digest_path).expect("read source digests"),
            generated.digests,
            "bless source digests after reviewing coverage"
        );
    }
    assert!(
        generated.unreviewed.is_empty(),
        "review source changes and coverage, then manually update reviewed_sha256:\n{}",
        generated.unreviewed.join("\n")
    );
}

#[test]
fn regeneration_preserves_review_and_detects_source_changes() {
    let source = "fn rewrite() {}\n";
    let digest = format!("{:x}", sha2::Sha256::digest(source.as_bytes()));
    let inventory = format!(
        "site\trewrite\tside_conditions\twidths\tcoverage\tanchor\treviewed_sha256\n\
         src/example.rs:99\tExample\tNone\t64\topen\tfn rewrite(\t{digest}\n"
    );
    let generated = generate(&inventory, |_| source.to_owned());
    assert!(generated.unreviewed.is_empty());
    assert_eq!(generated.inventory, inventory.replace(":99\t", ":1\t"));
    assert_eq!(generated.digests, format!("{digest}  src/example.rs\n"));
    let changed = generate(&generated.inventory, |_| {
        "\nfn rewrite() { changed(); }\n".to_owned()
    });
    assert_eq!(changed.unreviewed, ["src/example.rs: Example"]);
    assert_eq!(changed.inventory, inventory.replace(":99\t", ":2\t"));
    assert_ne!(changed.digests, generated.digests);
    let regenerated = generate(&changed.inventory, |_| {
        "\nfn rewrite() { changed(); }\n".to_owned()
    });
    assert_eq!(regenerated.unreviewed, changed.unreviewed);
    assert_eq!(regenerated.inventory, changed.inventory);
}
