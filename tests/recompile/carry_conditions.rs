use super::unsupported::code_image;
use super::*;

#[test]
fn printed_carry_chain_conditions_preserve_results() {
    let mut candidates = Vec::new();
    for (bits, prefix, add, sub) in [
        (8, vec![], 0x10, 0x18),
        (16, vec![0x66], 0x11, 0x19),
        (32, vec![], 0x11, 0x19),
        (64, vec![0x48], 0x11, 0x19),
    ] {
        for opcode in [add, sub] {
            for condition in 0..16 {
                for consumer in 0..3 {
                    // cmp rdx, rcx; adc/sbb rdi, rsi
                    let mut code = vec![0x48, 0x39, 0xca];
                    if bits == 8 {
                        code.push(0x40); // dil and sil, rather than the high bytes
                    }
                    code.extend(&prefix);
                    code.extend([opcode, 0xf7]);
                    if condition & 1 != 0 {
                        code.extend([0xeb, 0]);
                    }
                    match consumer {
                        0 => code.extend([0x0f, 0x90 | condition, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3]),
                        1 => code.extend([
                            0x70 | condition,
                            6,
                            0xb8,
                            0,
                            0,
                            0,
                            0,
                            0xc3,
                            0xb8,
                            1,
                            0,
                            0,
                            0,
                            0xc3,
                        ]),
                        _ => code.extend([
                            0xb8,
                            0,
                            0,
                            0,
                            0,
                            0xbf,
                            1,
                            0,
                            0,
                            0,
                            0x48,
                            0x0f,
                            0x40 | condition,
                            0xc7,
                            0xc3,
                        ]),
                    }
                    let image = code_image(&code);
                    let mut ir = synthetic_ir(
                        &format!("carry_{bits}_{opcode}_{condition}_{consumer}"),
                        [7, 6, 2, 1]
                            .into_iter()
                            .map(|index| Param {
                                index,
                                name: format!("arg{index}"),
                                ty: CType::U64,
                            })
                            .collect(),
                        CType::U64,
                        vec![],
                    );
                    ir.blocks = velk::lift::lift(&image, 0, code.len() as u64, &Default::default())
                        .unwrap();
                    velk::passes::optimize(&mut ir, false);
                    let mut analyzed = velk::analysis::analyze(&image, &image.functions[&0], None)
                        .unwrap()
                        .ir;
                    analyzed.name = ir.name.clone();
                    if bits == 64 {
                        for param in &analyzed.params {
                            if ![7, 6].contains(&param.index) || ![10, 11].contains(&condition) {
                                assert!(
                                    !param.ty.is_32_bit_int(),
                                    "{}: {param:?}",
                                    analyzed.render()
                                );
                            }
                        }
                    }
                    let inputs = (0..64)
                        .map(|trial| {
                            let edges = [0, 1, u64::MAX, 1 << (bits - 1), (1 << (bits - 1)) - 1];
                            vec![
                                if trial < 25 {
                                    edges[trial as usize % 5]
                                } else {
                                    eval::hash(trial, 0)
                                },
                                if trial < 25 {
                                    edges[trial as usize / 5]
                                } else {
                                    eval::hash(trial, 1)
                                },
                                trial % 2,
                                1,
                            ]
                        })
                        .collect();
                    let mut candidate = printed_candidate(analyzed, inputs);
                    candidate.ir = ir;
                    assert!(
                        !candidate.code.contains("unsupported"),
                        "{}",
                        candidate.code
                    );
                    assert!(!candidate.code.contains("undefined"), "{}", candidate.code);
                    candidates.push(candidate);
                }
            }
        }
    }
    check_candidates("carry_conditions", candidates, Mode::Registers, &[]);
}
