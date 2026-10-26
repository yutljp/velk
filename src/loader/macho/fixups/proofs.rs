//! One chained pointer in each supported format.

use object::LittleEndian;
use object::read::macho::{DyldChainedFixups, Fixup};

fn check_pointer(format: u16) {
    let next_mask = if matches!(format, 2 | 6) {
        0xfff
    } else {
        0x7ff
    };
    let raw = kani::any::<u64>() & !(next_mask << 51);
    let base: u64 = kani::any();
    let mut bytes = [0u8; 60];
    bytes[4..8].copy_from_slice(&28u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&8u32.to_le_bytes());
    bytes[36..40].copy_from_slice(&24u32.to_le_bytes());
    bytes[40..42].copy_from_slice(&4096u16.to_le_bytes());
    bytes[42..44].copy_from_slice(&format.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    let fixups = DyldChainedFixups::parse(LittleEndian, &bytes).unwrap();
    let mut segments = fixups.segments(LittleEndian).unwrap();
    let segment = segments.next().unwrap().unwrap();
    let data = raw.to_le_bytes();
    let mut pointers = segment.fixups(LittleEndian, base, &data);
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
        }
        _ => panic!("supported formats decode to rebase or bind"),
    }
    let next = if wide {
        ((raw >> 51) & 0xfff) * 4
    } else {
        ((raw >> 51) & 0x7ff) * if matches!(format, 7 | 10) { 4 } else { 8 }
    };
    let end = pointers.next();
    if next == 0 {
        assert!(matches!(end, Ok(None)));
    } else {
        assert!(end.is_err());
    }
    assert!(matches!(pointers.next(), Ok(None)));
}

macro_rules! pointer_proof {
    ($name:ident, $format:literal) => {
        #[kani::proof]
        #[kani::unwind(3)]
        fn $name() {
            check_pointer($format);
        }
    };
}

pointer_proof!(chained_pointer_arm64e, 1);
pointer_proof!(chained_pointer_64, 2);
pointer_proof!(chained_pointer_64_offset, 6);
pointer_proof!(chained_pointer_arm64e_kernel, 7);
pointer_proof!(chained_pointer_arm64e_userland, 9);
pointer_proof!(chained_pointer_arm64e_firmware, 10);
pointer_proof!(chained_pointer_arm64e_userland24, 12);
