//! CLI listing and code presentation.
use crate::terminal::{Language, Terminal};
use serde_json::json;
use velk::addr;
use velk::service::{Binary, Failure};

pub(crate) fn report_failures(failures: &[Failure]) {
    if failures.is_empty() {
        return;
    }
    let terminal = Terminal::stderr();
    eprintln!(
        "{}",
        terminal.warning(&format!(
            "{} functions could not be lifted:",
            failures.len()
        ))
    );
    for failure in failures {
        eprintln!(
            "  {}: {}",
            terminal.address(&addr::format(failure.addr)),
            failure.error
        );
    }
}

pub(crate) fn print_code(
    binary: &Binary,
    addr: u64,
    requested_name: &str,
    code: &str,
    language: Language,
) {
    let terminal = Terminal::stdout();
    if !terminal.interactive() {
        print!("{code}");
        return;
    }
    let functions = binary.functions();
    let name = functions
        .iter()
        .find(|function| function.addr == addr)
        .and_then(|function| function.name.as_deref())
        .unwrap_or(requested_name);
    let title = match language {
        Language::C => "Pseudo-C",
        Language::Ir => "IR",
        Language::Disassembly => "Disassembly",
    };
    let metadata = format!(
        "{} · {} · {}",
        binary.path().display(),
        binary.image().isa,
        addr::format(addr),
    );
    print!(
        "{}",
        terminal.block(&format!("{title}  {name}"), &metadata, code, language)
    );
}

fn print_functions_terminal(binary: &Binary, limit: usize, terminal: Terminal) {
    let image = binary.image();
    let functions = binary.functions();
    print_slices(image);
    let named = functions
        .iter()
        .filter(|function| function.name.is_some())
        .count();
    println!(
        "{}  {}",
        terminal.heading("Functions"),
        binary.path().display()
    );
    println!(
        "{}",
        terminal.muted(&format!(
            "{} · {} · entry {} · {} sections",
            image.format,
            image.isa,
            image.entry.map_or("-".to_owned(), addr::format),
            image.sections.len(),
        ))
    );
    println!(
        "{}\n",
        terminal.muted(&format!(
            "{} functions · {named} named",
            image.functions.len()
        ))
    );
    println!(
        "{}",
        terminal.heading(&format!(
            "{:<18} {:>10}  {:<22}  Name",
            "Address", "Size", "Sources",
        ))
    );
    for function in functions.iter().take(limit) {
        let sources = function
            .sources
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{} {:>10}  {}  {}",
            terminal.address(&format!("{:<18}", addr::format(function.addr))),
            function
                .size
                .map_or("?".to_owned(), |size| size.to_string()),
            terminal.muted(&format!("{sources:<22}")),
            format_args!(
                "{}{}",
                function.name.as_deref().unwrap_or("<unnamed>"),
                library_evidence(function)
            ),
        );
    }
    println!();
    let shown = image.functions.len().min(limit);
    if shown < image.functions.len() {
        println!(
            "{}\n",
            terminal.muted(&format!(
                "Showing {shown} of {} functions",
                image.functions.len()
            ))
        );
    }
}

fn print_sections_terminal(binary: &Binary, terminal: Terminal) {
    let image = binary.image();
    println!(
        "{}  {}",
        terminal.heading("Sections"),
        binary.path().display()
    );
    println!(
        "{}\n",
        terminal.muted(&format!(
            "{} · {} · {} sections",
            image.format,
            image.isa,
            image.sections.len()
        ))
    );
    println!(
        "{}",
        terminal.heading(&format!(
            "{:<18} {:>10} {:>14}  {:<4} Section",
            "Address", "Size", "File", "Exec",
        ))
    );
    for section in &image.sections {
        println!(
            "{} {:>10} {:>14}  {:<4} {}",
            terminal.address(&format!("{:<18}", addr::format(section.vaddr))),
            section.size,
            section.file_offset.map_or("-".to_owned(), addr::format),
            if section.executable { "x" } else { "" },
            section.name,
        );
    }
    println!();
}

pub(crate) fn print_functions_json(binary: &Binary, limit: usize) {
    let image = binary.image();
    let summary = json!({
        "format": image.format,
        "arch": image.isa,
        "slices": image.slices,
        "sliceOffset": image.slice_offset,
        "entry": image.entry.map(addr::format),
        "sections": image.sections.len(),
        "functionCount": image.functions.len(),
        "functions": binary.functions().iter().take(limit).collect::<Vec<_>>(),
    });
    println!("{summary:#}");
}

pub(crate) fn print_functions(binary: &Binary, limit: usize) {
    let terminal = Terminal::stdout();
    if terminal.interactive() {
        print_functions_terminal(binary, limit, terminal);
        return;
    }
    let image = binary.image();
    let functions = binary.functions();
    println!(
        "format: {}, arch: {}, entry: {}, sections: {}, functions: {}, named: {}",
        image.format,
        image.isa,
        image.entry.map_or("-".to_owned(), addr::format),
        image.sections.len(),
        image.functions.len(),
        functions.iter().filter(|f| f.name.is_some()).count(),
    );
    print_slices(image);
    println!("{:<14} {:>10} {:<26} sources", "addr", "size", "name");
    for function in functions.iter().take(limit) {
        let name: String = function
            .name
            .as_deref()
            .unwrap_or("<unnamed>")
            .chars()
            .take(26)
            .collect();
        let sources: Vec<String> = function.sources.iter().map(ToString::to_string).collect();
        println!(
            "{:<14} {:>10} {:<26} {}",
            addr::format(function.addr),
            function
                .size
                .map_or("?".to_owned(), |size| size.to_string()),
            name,
            format_args!("{}{}", sources.join(","), library_evidence(function)),
        );
    }
}

pub(crate) fn print_sections(binary: &Binary) {
    let terminal = Terminal::stdout();
    if terminal.interactive() {
        print_sections_terminal(binary, terminal);
        return;
    }
    println!(
        "{:<16} {:>12} {:>10} {:>12}  exec",
        "section", "addr", "size", "file"
    );
    for section in &binary.image().sections {
        println!(
            "{:<16} 0x{:010x} {:>10} {:>12}  {}",
            section.name,
            section.vaddr,
            section.size,
            section.file_offset.map_or("-".to_owned(), addr::format),
            if section.executable { "x" } else { "" },
        );
    }
}

fn print_slices(image: &velk::loader::Image) {
    if !image.slices.is_empty() {
        let names: Vec<&str> = image
            .slices
            .iter()
            .map(|slice| slice.arch.as_str())
            .collect();
        println!(
            "slices: {}, selected offset: {:#x}",
            names.join(", "),
            image.slice_offset
        );
    }
}

pub(crate) fn print_identification(
    binary: &Binary,
    identification: &velk::service::Identification,
    limit: usize,
) {
    let terminal = Terminal::stdout();
    if terminal.interactive() {
        println!(
            "{}  {}",
            terminal.heading("Identified functions"),
            binary.path().display()
        );
        println!(
            "{}\n",
            terminal.muted(&format!(
                "{} · {}",
                binary.image().format,
                binary.image().isa
            ))
        );
        println!(
            "{}",
            terminal.heading(&format!(
                "{:<18} {:>10}  Match (current name)",
                "Address", "Size"
            ))
        );
    }
    for hit in identification.matches.iter().take(limit) {
        if terminal.interactive() {
            println!(
                "{} {:>10}  {}  (currently: {})",
                terminal.address(&format!("{:<18}", addr::format(hit.addr))),
                hit.size.map_or("?".to_owned(), |size| size.to_string()),
                format_args!("{} [{}]", hit.matched, evidence_text(&hit.evidence)),
                hit.current.as_deref().unwrap_or("unnamed"),
            );
            continue;
        }
        println!(
            "{:<14} {:>6}  {}  (currently: {})",
            addr::format(hit.addr),
            hit.size.map_or("?".to_owned(), |size| size.to_string()),
            format_args!(
                "{} [{}; exact]",
                hit.matched,
                hit.evidence
                    .candidates
                    .iter()
                    .map(|candidate| candidate.set.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            hit.current.as_deref().unwrap_or("unnamed")
        );
    }
    if terminal.interactive() {
        println!();
    }
    println!(
        "identified {} of {} functions",
        identification.matches.len(),
        binary.image().functions.len()
    );
    if terminal.interactive() {
        println!();
    }
    for (address, evidence) in identification.candidates.iter().take(limit) {
        println!("{}: {}", addr::format(*address), evidence_text(evidence));
    }
    report_failures(&identification.failures);
}

fn evidence_text(evidence: &velk::sigs::Evidence) -> String {
    let certainty = match evidence.certainty {
        velk::sigs::Certainty::Exact => "exact",
        velk::sigs::Certainty::Ambiguous => "ambiguous",
        velk::sigs::Certainty::Unconfirmed => "unconfirmed",
    };
    let candidates: Vec<_> = evidence
        .candidates
        .iter()
        .map(|candidate| format!("{} ({})", candidate.name, candidate.set))
        .collect();
    format!("{certainty}: {}", candidates.join(", "))
}

fn library_evidence(function: &velk::loader::Function) -> String {
    function
        .library
        .as_ref()
        .map(|evidence| format!(" [{}]", evidence_text(evidence)))
        .unwrap_or_default()
}
