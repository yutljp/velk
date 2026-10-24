use super::*;

#[test]
fn printed_negative_local_comparisons_keep_the_machine_result() {
    let scratch = scratch_dir("negative-local-comparisons");
    let source = scratch.join("compare.c");
    let object = scratch.join("compare.o");
    std::fs::write(&source, "int negative(int x) { int y = -19; if (y > 5) return x + 7; return 3; }\nint bound(int x) { int y = 0; if (y >= -1) return x + 7; return 3; }\nint loop(int x) { int result = 0; for (int y = 0; y >= -1; --y) result += x; return result; }\n").unwrap();
    let compiled = Command::new(compiler())
        .args(["-target", "x86_64-linux-gnu", "-O0", "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let mut binary = Binary::open(&object).unwrap();
    let mut candidates = Vec::new();
    for name in ["negative", "bound", "loop"] {
        let address = binary.find(name).unwrap().addr;
        let ir = binary.analysis(address, None).unwrap().ir.clone();
        let inputs = [0, 1, 9, u32::MAX as u64].map(|x| vec![x]).to_vec();
        let mut candidate = printed_candidate(ir, inputs);
        candidate.code = binary.decompile(address, None, None).unwrap();
        for input in &candidate.inputs {
            let expected = match name {
                "negative" => 3,
                "bound" => input[0].wrapping_add(7) as u32 as u64,
                _ => input[0].wrapping_mul(2) as u32 as u64,
            };
            let setup = eval::Setup {
                seed: 0,
                convention: eval::Convention {
                    arguments: &[7],
                    clobbered: &[],
                },
                registers: &[(7, input[0])],
                memory: &[],
                step_limit: 1000,
            };
            assert!(
                matches!(eval::run(&candidate.ir, &setup), Outcome::Return { value, .. } if value as u32 as u64 == expected),
                "{name}: expected {expected}\n{}",
                candidate.code
            );
        }
        candidates.push(candidate);
    }
    check_candidates(
        "negative-local-comparisons",
        candidates,
        Mode::Registers,
        &[],
    );
    std::fs::remove_dir_all(scratch).ok();
}
