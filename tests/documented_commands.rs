//! Run fixture-based CLI examples from the documentation.

use std::fs;
use std::process::Command;

#[test]
fn fixture_commands_run() {
    let mut count = 0;
    let mut paths = vec!["README.md".into(), "README.ja.md".into()];
    for entry in fs::read_dir("docs").unwrap() {
        paths.push(entry.unwrap().path());
    }
    for path in paths {
        if path.extension().and_then(|extension| extension.to_str()) != Some("md") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        for line in text
            .lines()
            .filter(|line| line.starts_with("velk ") && line.contains("tests/"))
        {
            let mut arguments = line.split_whitespace();
            assert_eq!(arguments.next(), Some("velk"));
            let output = Command::new(env!("CARGO_BIN_EXE_velk"))
                .args(arguments)
                .args(["--cache", "off"])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}: {line}: {}",
                path.display(),
                String::from_utf8_lossy(&output.stderr)
            );
            count += 1;
        }
    }
    assert!(count >= 6);
}
