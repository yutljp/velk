//! Compiler execution for integration tests with caller-supplied arguments and input.

use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};

pub fn run(command: &mut Command, source: Option<&str>) -> Output {
    use std::io::Write as _;

    let Some(source) = source else {
        return command.output().expect("C compiler");
    };
    let mut compiler = command
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("C compiler");
    compiler
        .stdin
        .take()
        .expect("standard input")
        .write_all(source.as_bytes())
        .expect("writing to C compiler");
    compiler.wait_with_output().expect("C compiler")
}

pub fn compile_file(command: &mut Command, path: &Path, source: &str) {
    fs::write(path, source).expect("writing compiler source");
    let compiled = run(command, None);
    assert!(compiled.status.success(), "{compiled:?}");
}

pub fn compile_x86_64_assembly(compiler: &Path, assembly: &Path, object: &Path, source: &str) {
    compile_file(
        Command::new(compiler)
            .args(["--target=x86_64-unknown-linux-gnu", "-c"])
            .arg(assembly)
            .arg("-o")
            .arg(object),
        assembly,
        source,
    );
}
