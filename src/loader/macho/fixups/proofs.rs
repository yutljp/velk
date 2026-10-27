//! Bounded chained pointers in each supported format.

use object::LittleEndian;
use object::read::macho::{DyldChainedFixups, Fixup};

struct RebaseCases {
    authenticated: bool,
    overflow: bool,
}

fn starts(format: u16) -> [u8; 60] {
    let mut bytes = [0u8; 60];
    bytes[4..8].copy_from_slice(&28u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&8u32.to_le_bytes());
    bytes[36..40].copy_from_slice(&24u32.to_le_bytes());
    bytes[40..42].copy_from_slice(&4096u16.to_le_bytes());
    bytes[42..44].copy_from_slice(&format.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes
}

fn check_pointer(format: u16) -> RebaseCases {
    let mut cases = RebaseCases {
        authenticated: false,
        overflow: false,
    };
    let next_mask = if matches!(format, 2 | 6) {
        0xfff
    } else {
        0x7ff
    };
    let raw = kani::any::<u64>() & !((next_mask & !1) << 51);
    let base: u64 = kani::any();
    let bytes = starts(format);
    let fixups = DyldChainedFixups::parse(LittleEndian, &bytes).unwrap();
    let mut segments = fixups.segments(LittleEndian).unwrap();
    let segment = segments.next().unwrap().unwrap();
    let pointer_bytes = raw.to_le_bytes();
    let mut pointers = segment.fixups(LittleEndian, base, &pointer_bytes);
    let (offset, pointer) = pointers.next().unwrap().unwrap();
    assert_eq!(offset, 0);
    let wide = matches!(format, 2 | 6);
    let bind = raw & (1u64 << if wide { 63 } else { 62 }) != 0;
    match pointer {
        Fixup::Rebase(rebase) => {
            assert!(!bind);
            let authenticated = !wide && raw >> 63 != 0;
            assert_eq!(rebase.auth.is_some(), authenticated);
            let absolute = matches!(format, 1 | 2 | 10) && !authenticated;
            let low = if authenticated {
                raw & 0xffff_ffff
            } else if wide {
                raw & 0xf_ffff_ffff
            } else {
                raw & 0x7ff_ffff_ffff
            };
            let high = if authenticated {
                0
            } else if wide {
                (raw >> 36) & 0xff
            } else {
                (raw >> 43) & 0xff
            };
            let expected = if absolute {
                Some(low | high << 56)
            } else {
                low.checked_add(base).map(|target| target | high << 56)
            };
            assert_eq!(super::rebase_value(base, format, raw, rebase), expected);
            cases.authenticated = authenticated;
            cases.overflow = expected.is_none();
            kani::cover!(!authenticated, "an unauthenticated pointer is rebased");
        }
        Fixup::Bind(binding) => {
            assert!(bind);
            assert_eq!(binding.auth.is_some(), !wide && raw >> 63 != 0);
            let ordinal_mask = if wide || format == 12 {
                0xff_ffff
            } else {
                0xffff
            };
            assert_eq!(binding.ordinal as u64, raw & ordinal_mask);
            let addend = if wide {
                ((raw >> 24) & 0xff) as i32
            } else if raw >> 63 != 0 {
                0
            } else {
                (((raw >> 32) as i32) << 13) >> 13
            };
            assert_eq!(binding.addend, addend);
            kani::cover!(binding.ordinal != 0, "a nonzero ordinal is bound");
        }
        _ => panic!("supported formats decode to rebase or bind"),
    }
    let next = (raw >> 51) & next_mask;
    let end = pointers.next();
    if next == 0 {
        assert!(matches!(end, Ok(None)));
        kani::cover!(true, "a zero link terminates");
    } else {
        assert!(end.is_err());
        kani::cover!(true, "an out-of-range link is rejected");
    }
    assert!(matches!(pointers.next(), Ok(None)));
    cases
}

macro_rules! pointer_proof {
    ($name:ident, $format:literal, $unwind:literal, [$($case:ident),*]) => {
        #[kani::proof]
        #[kani::unwind($unwind)]
        fn $name() {
            let cases = check_pointer($format);
            $(kani::cover!(cases.$case);)*
            let _ = cases;
        }
    };
}

pointer_proof!(chained_pointer_arm64e, 1, 3, [authenticated, overflow]);
pointer_proof!(chained_pointer_64, 2, 3, []);
pointer_proof!(chained_pointer_64_offset, 6, 3, [overflow]);
pointer_proof!(
    chained_pointer_arm64e_kernel,
    7,
    4,
    [authenticated, overflow]
);
pointer_proof!(
    chained_pointer_arm64e_userland,
    9,
    5,
    [authenticated, overflow]
);
pointer_proof!(
    chained_pointer_arm64e_firmware,
    10,
    6,
    [authenticated, overflow]
);
pointer_proof!(
    chained_pointer_arm64e_userland24,
    12,
    7,
    [authenticated, overflow]
);

#[kani::proof]
#[kani::unwind(3)]
fn chained_pointer_links() {
    let format: u16 = kani::any();
    kani::assume(matches!(format, 1 | 2 | 6 | 7 | 9 | 10 | 12));
    let stride = if matches!(format, 2 | 6 | 7 | 10) {
        4
    } else {
        8
    };
    let raw = (8u64 / stride) << 51;
    let bytes = starts(format);
    let fixups = DyldChainedFixups::parse(LittleEndian, &bytes).unwrap();
    let mut segments = fixups.segments(LittleEndian).unwrap();
    let segment = segments.next().unwrap().unwrap();
    let mut pointer_bytes = [0u8; 16];
    pointer_bytes[..8].copy_from_slice(&raw.to_le_bytes());
    let mut pointers = segment.fixups(LittleEndian, 0, &pointer_bytes);
    for expected in [0, 8] {
        let (offset, pointer) = pointers.next().unwrap().unwrap();
        assert_eq!(offset, expected);
        let Fixup::Rebase(rebase) = pointer else {
            panic!("a link with no payload is a rebase");
        };
        assert_eq!(rebase.target_offset, 0);
        assert!(rebase.auth.is_none());
    }
    assert!(matches!(pointers.next(), Ok(None)));
    kani::cover!(
        stride == 4,
        "a four-byte-stride link reaches a second pointer"
    );
    kani::cover!(
        stride == 8,
        "an eight-byte-stride link reaches a second pointer"
    );
}
