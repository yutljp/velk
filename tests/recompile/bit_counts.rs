use super::*;

#[test]
fn printed_bit_counts_define_zero_and_truncate_the_input() {
    let mut candidates = Vec::new();
    for bits in [8, 16, 32, 64] {
        let mask = u64::MAX >> (64 - bits);
        let inputs: Vec<Vec<u64>> = [0, 1, 2, mask, mask >> 1, !mask, 1 << (bits - 1), u64::MAX]
            .into_iter()
            .map(|value| vec![value])
            .collect();
        for operation in [
            Operation::CountLeadingZeros(bits),
            Operation::CountTrailingZeros(bits),
        ] {
            let ir = synthetic_ir(
                &format!("count_{operation:?}"),
                vec![Param {
                    index: 7,
                    name: "value".to_owned(),
                    ty: CType::U64,
                }],
                CType::U64,
                vec![Stmt::Ret {
                    value: Expr::Apply {
                        op: operation,
                        args: vec![Expr::reg(7, 64)],
                    },
                }],
            );
            let candidate = printed_candidate(ir, inputs.clone());
            assert!(
                candidate.code.contains(&format!(", {bits})")),
                "{}",
                candidate.code
            );
            candidates.push(candidate);
        }
    }
    check_candidates("bit-counts", candidates, Mode::Registers, &[]);
}
