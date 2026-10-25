//! Compiler execution for integration tests with caller-supplied arguments and input.

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
