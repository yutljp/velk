//! Integer instruction checks in a Docker Linux i386 process.

use std::fmt::Write;
use std::fs;
use std::process::Command;

use super::{lifted, value};
use crate::ir::eval;
use crate::loader::Isa;

#[test]
fn integer_instructions_match_linux_i386() {
    if !super::docker_available("linux/386", "i386/alpine", "i686") {
        return;
    }
    let directory = std::env::current_dir()
        .expect("the test has a working directory")
        .join("target/i386-hardware");
    fs::create_dir_all(&directory).expect("create i386 processor test directory");
    let instructions: &[&[u8]] = &[
        &[0x40],
        &[0x48],
        &[0x01, 0xd8],
        &[0x29, 0xd8],
        &[0x31, 0xd8],
        &[0x21, 0xd8],
        &[0x09, 0xd8],
        &[0x0f, 0xaf, 0xc3],
        &[0xf7, 0xd8],
        &[0xf7, 0xd0],
        &[0xd3, 0xe0],
        &[0xd3, 0xe8],
        &[0xd3, 0xf8],
        &[0x66, 0x01, 0xd8],
        &[0x00, 0xdc],
        &[0x0f, 0xbe, 0xc4],
        &[0x39, 0xd8, 0x0f, 0x9c, 0xc0],
        &[0x39, 0xd8, 0x0f, 0x92, 0xc0],
        &[0x39, 0xd8, 0x11, 0xd8],
        &[0x39, 0xd8, 0x19, 0xd8],
    ];
    let mut assembly = String::from(".text\n.globl _start\n_start:\n");
    let mut expected = Vec::new();
    for instruction in instructions {
        let ir =
            lifted(Isa::I386, [*instruction, &[0xc3]].concat()).expect("integer instruction lifts");
        for seed in 0..128 {
            let a = value(seed, 0) as u32;
            let b = value(seed, 1) as u32;
            let count = value(seed, 2) as u32;
            writeln!(
                assembly,
                "mov ${a}, %eax\nmov ${b}, %ebx\nmov ${count}, %ecx"
            )
            .unwrap();
            assembly.push_str(".byte ");
            for (index, byte) in instruction.iter().enumerate() {
                if index != 0 {
                    assembly.push(',');
                }
                write!(assembly, "{byte}").unwrap();
            }
            assembly.push_str("\npush %eax\nmov $4, %eax\nmov $1, %ebx\nmov %esp, %ecx\nmov $4, %edx\nint $0x80\nadd $4, %esp\n");
            let registers = [(0, u64::from(a)), (3, u64::from(b)), (1, u64::from(count))];
            let setup = super::setup(&registers);
            let eval::Outcome::Return { value, .. } = eval::run(&ir, &setup) else {
                panic!("integer instruction did not return: {instruction:02x?}");
            };
            expected.extend_from_slice(&(value as u32).to_le_bytes());
        }
    }
    assembly.push_str("mov $1, %eax\nxor %ebx, %ebx\nint $0x80\n");
    fs::write(directory.join("check.s"), assembly).expect("write processor test assembly");
    for (program, arguments) in [
        (
            "clang",
            vec!["--target=i686-linux-gnu", "-c", "check.s", "-o", "check.o"],
        ),
        (
            "ld.lld",
            vec!["-m", "elf_i386", "-static", "check.o", "-o", "check"],
        ),
    ] {
        let output = Command::new(program)
            .args(arguments)
            .current_dir(&directory)
            .output();
        let Ok(output) = output else {
            eprintln!("{program} unavailable; i386 processor comparison skipped");
            return;
        };
        assert!(
            output.status.success(),
            "{program}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output = super::docker_run("linux/386", "i386/alpine", &directory, "check");
    assert!(
        output.status.success(),
        "i386 execution: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout.len(),
        expected.len(),
        "each instruction must produce a result"
    );
    let comparisons = output
        .stdout
        .as_chunks::<4>()
        .0
        .iter()
        .zip(expected.as_chunks::<4>().0);
    for (index, (actual, expected)) in comparisons.enumerate() {
        assert_eq!(
            actual,
            expected,
            "instruction {:?}, seed {}",
            instructions[index / 128],
            index % 128
        );
    }
    eprintln!(
        "{} i386 integer processor comparisons passed",
        expected.len() / 4
    );
}
