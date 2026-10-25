mod common;

use object::Object;

use velk::analysis::prototypes;
use velk::ir::Stmt;
use velk::loader::{Format, NameSource};
use velk::service::Binary;

#[test]
fn pe_import_and_call_coverage() {
    let mut report = String::new();
    for fixture in common::fixtures() {
        let Ok(mut binary) = Binary::open(&common::fixtures_dir().join(&fixture)) else {
            continue;
        };
        if binary.image().format != Format::Pe {
            continue;
        }
        let image = binary.image();
        let bytes = std::fs::read(common::fixtures_dir().join(&fixture)).unwrap();
        let file = object::File::parse(bytes.as_slice()).unwrap();
        let mut imports = Vec::new();
        for import in file.imports().unwrap() {
            let import = import.unwrap();
            let name = match import.name() {
                object::NameOrOrdinal::Name(name) => String::from_utf8_lossy(name).into_owned(),
                object::NameOrOrdinal::Ordinal(ordinal) => format!("#{ordinal}"),
            };
            imports.push(format!(
                "{}!{name}",
                String::from_utf8_lossy(import.library())
            ));
        }
        imports.sort();
        let known = imports
            .iter()
            .filter(|name| prototypes::for_image(name.rsplit_once('!').unwrap().1, image).is_some())
            .count();
        report.push_str(&format!(
            "{}: imports {known}/{}\n",
            fixture.display(),
            imports.len()
        ));
        for name in &imports {
            report.push_str(&format!(
                "  {name}: {}\n",
                if prototypes::for_image(name.rsplit_once('!').unwrap().1, image).is_some() {
                    "known"
                } else {
                    "unknown"
                }
            ));
        }
        let addresses: Vec<_> = image
            .functions
            .values()
            .filter(|function| !function.sources.contains(&NameSource::Plt))
            .map(|function| function.addr)
            .collect();
        let mut calls = Vec::new();
        let mut known_calls = 0;
        let mut failures = 0;
        for address in addresses {
            let Ok(analysis) = binary.analysis(address, None) else {
                failures += 1;
                continue;
            };
            let statements: Vec<_> = analysis
                .ir
                .blocks
                .iter()
                .flat_map(|block| block.stmts.clone())
                .collect();
            for (index, statement) in statements.iter().enumerate() {
                if matches!(statement, Stmt::Call { .. }) {
                    let known = prototypes::called(binary.image(), statement).is_some();
                    known_calls += usize::from(known);
                    calls.push(format!(
                        "  {address:#x}:{index}: {}\n",
                        if known { "known" } else { "unknown" }
                    ));
                }
            }
        }
        report.push_str(&format!(
            "  calls {}/{}, lift failures {failures}\n",
            known_calls,
            calls.len()
        ));
        for call in calls {
            report.push_str(&call);
        }
    }
    if let Some(difference) = common::check_expected(
        &common::root().join("tests/golden/pe_prototypes.txt"),
        &report,
    ) {
        panic!("{difference}");
    }
}
