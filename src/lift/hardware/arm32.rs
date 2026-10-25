//! Runs A32 and T32 integer code through ARM Linux and the IR interpreter.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::ir::FunctionIr;
use crate::ir::eval;
use crate::loader;

#[test]
fn integer_instructions_match_arm_linux() {
    use std::fmt::Write as _;

    let probe = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--platform",
            "linux/arm/v7",
            "alpine:3.20",
            "uname",
            "-m",
        ])
        .output();
    match probe {
        Ok(output) if output.status.success() && output.stdout.starts_with(b"armv7") => {}
        other => {
            eprintln!("skipping ARM32 hardware check: Docker linux/arm/v7 unavailable: {other:?}");
            return;
        }
    }
    let scratch = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/arm32-hardware");
    fs::create_dir_all(&scratch).unwrap();
    let instructions = [
        "add r0, r0, r1",
        "sub r0, r0, r1",
        "rsb r0, r0, #0",
        "mul r0, r0, r1",
        "and r0, r0, r1",
        "orr r0, r0, r1",
        "eor r0, r0, r1",
        "bic r0, r0, r1",
        "lsl r0, r0, r1",
        "lsr r0, r0, r1",
        "asr r0, r0, r1",
        "ror r0, r0, r1",
        "sxtb r0, r0",
        "sxth r0, r0",
        "uxtb r0, r0",
        "uxth r0, r0",
        "sxtb r0, r0, ror #8",
        "sxth r0, r0, ror #16",
        "uxtb r0, r0, ror #24",
        "uxth r0, r0, ror #8",
        "ubfx r0, r0, #4, #4",
        "sdiv r0, r0, r1",
        "udiv r0, r0, r1",
        "cmp r0, r1\n{it}movlt r0, r1",
        "vmov s0, r0\nvmov s1, r1\nvadd.f32 s0, s0, s1\nvmov r0, s0",
        "vmov s0, r0\nvmov s1, r1\nvsub.f32 s0, s0, s1\nvmov r0, s0",
        "vmov s0, r0\nvmov s1, r1\nvmla.f32 s0, s0, s1\nvmov r0, s0",
        "vmov s0, r0\nvcvt.f64.f32 d16, s0\nvmov s0, r1\nvcvt.f64.f32 d17, s0\nvadd.f64 d0, d16, d17\nvcvt.f32.f64 s0, d0\nvmov r0, s0",
        "vmov s0, r0\nvcvt.f64.f32 d0, s0\nvcvt.s32.f64 s0, d0\nvmov r0, s0",
        "vmov s0, r0\nvmov s1, r1\nvcmp.f32 s0, s1\nvmrs APSR_nzcv, fpscr\nmov r0, #0\n{it}movlt r0, #1",
        "vmov s0, r0\nvcvt.f64.f32 d0, s0\nvmov s2, r1\nvcvt.f64.f32 d1, s2\nvcmp.f64 d0, d1\nvmrs APSR_nzcv, fpscr\nmov r0, #0\n{it}movlt r0, #1",
        "rev r0, r0",
    ];
    let edges = [
        0u32,
        1,
        7,
        31,
        32,
        33,
        255,
        256,
        0x3f80_0000,
        0x3f80_0001,
        0xbf7f_fffe,
        0x7f80_0000,
        0xff80_0000,
        0xbfc0_0000,
        0x7fc0_0000,
        0x7fff_ffff,
        0x8000_0000,
        u32::MAX,
    ];
    for mode in ["arm", "thumb"] {
        let entry_mode = if mode == "thumb" { ".thumb_func\n" } else { "" };
        let mut source = format!(
            ".syntax unified\n.cpu cortex-a15\n.fpu neon-vfpv4\n.{mode}\n.text\n.global _start\n.type _start, %function\n{entry_mode}_start:\nmovw r8, #:lower16:results\nmovt r8, #:upper16:results\n"
        );
        let mut inputs = Vec::new();
        for index in 0..instructions.len() {
            for &left in &edges {
                for &right in &edges {
                    writeln!(source, "movw r0, #{}\nmovt r0, #{}\nmovw r1, #{}\nmovt r1, #{}\nbl case_{index}\nstr r0, [r8], #4", left & 65535, left >> 16, right & 65535, right >> 16).unwrap();
                    inputs.push((index, left, right));
                }
            }
        }
        let size = inputs.len() * 4;
        writeln!(source, "mov r0, #1\nldr r1, =results\nmovw r2, #{size}\nmov r7, #4\nsvc #0\nmov r0, #0\nmov r7, #1\nsvc #0\n.ltorg").unwrap();
        let indexed = instructions.iter().enumerate();
        for (index, instruction) in indexed {
            let instruction =
                instruction.replace("{it}", if mode == "thumb" { "it lt\n" } else { "" });
            if mode == "thumb" {
                source.push_str(".thumb_func\n");
            }
            writeln!(source, ".type case_{index}, %function\ncase_{index}:\n{instruction}\nbx lr\n.size case_{index}, .-case_{index}").unwrap();
        }
        writeln!(source, ".bss\n.balign 4\nresults: .space {size}").unwrap();
        let assembly = scratch.join(format!("{mode}.s"));
        let executable = scratch.join(format!("{mode}.elf"));
        fs::write(&assembly, source).unwrap();
        let build = Command::new("clang")
            .args([
                "--target=armv7a-linux-gnueabihf",
                "-fuse-ld=lld",
                "-nostdlib",
                "-static",
                "-Wl,-e,_start",
            ])
            .arg(&assembly)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            build.status.success(),
            "{}",
            String::from_utf8_lossy(&build.stderr)
        );
        let output = Command::new("docker")
            .args(["run", "--rm", "--platform", "linux/arm/v7", "-v"])
            .arg(format!("{}:/check:ro", scratch.display()))
            .args(["alpine:3.20", &format!("/check/{mode}.elf")])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout.len(), size);
        let image = loader::load(&executable).unwrap();
        let mut functions = Vec::new();
        let indexed = instructions.iter().enumerate();
        for (index, instruction) in indexed {
            let name = format!("case_{index}");
            let function = image
                .functions
                .values()
                .find(|function| function.name.as_deref() == Some(&name))
                .unwrap();
            let mut ir = FunctionIr::single_block(image.isa, Vec::new());
            ir.blocks = match super::lift(
                &image,
                function.addr,
                function.size.unwrap(),
                &HashSet::new(),
            ) {
                Ok(blocks) => blocks,
                Err(error) => panic!("{mode} {instruction}: not lifted: {error}"),
            };
            assert_eq!(
                super::unsupported(&ir),
                None,
                "{mode} {instruction}: {}",
                ir.render()
            );
            assert!(!super::branches_on_unknown_flags(&ir), "{}", ir.render());
            functions.push(ir);
        }
        let mut compared = 0;
        let (results, remainder) = output.stdout.as_chunks::<4>();
        assert!(remainder.is_empty());
        let comparisons = inputs.iter().zip(results);
        for ((index, left, right), bytes) in comparisons {
            let ir = &functions[*index];
            let expected = u32::from_le_bytes(*bytes);
            let registers = [(0, u64::from(*left)), (1, u64::from(*right))];
            let result = eval::run(ir, &super::setup(&registers));
            compared += 1;
            let floating_result = instructions[*index].contains("vmov r0, s0")
                && !instructions[*index].contains("vcvt.s32");
            assert!(
                matches!(result, eval::Outcome::Return { value, .. } if value == u64::from(expected)
                    || (floating_result && f32::from_bits(value as u32).is_nan()
                        && f32::from_bits(expected).is_nan())),
                "{mode} {} ({left:#x}, {right:#x}): processor {expected:#x}, IR {result:?}",
                instructions[*index]
            );
        }
        assert_eq!(compared, instructions.len() * edges.len() * edges.len());
        eprintln!("{mode}: {compared} ARM Linux integer results agree");
    }
}
