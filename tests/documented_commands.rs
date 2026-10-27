//! Run fixture-based CLI examples from the documentation.

use std::fs;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;

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

#[test]
fn fixture_scripts_run() {
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
        let mut blocks = text.split("```");
        while let Some(block) = blocks.next() {
            let Some(code) = blocks.next() else { break };
            let _ = block;
            let Some((language, script)) = code.split_once('\n') else {
                continue;
            };
            if !matches!(language, "js" | "javascript")
                || !(script.contains("tests/fixtures/") || script.contains("tests/data/"))
            {
                continue;
            }
            let mut child = Command::new(env!("CARGO_BIN_EXE_velk"))
                .arg("--serve")
                .env("VELK_CACHE", "off")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let request = serde_json::json!({"id": 1, "code": script});
            writeln!(child.stdin.take().unwrap(), "{request}").unwrap();
            let output = child.wait_with_output().unwrap();
            let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert!(
                output.status.success() && response.get("error").is_none(),
                "{}: {response}",
                path.display()
            );
            count += 1;
        }
    }
    assert!(count >= 12);
}
