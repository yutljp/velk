//! ARM ELF import linkage instruction decoding.

pub(crate) fn slot(words: [u32; 3], address: u32) -> Option<u32> {
    if words[0] & 0xffff_f000 != 0xe28f_c000
        || words[1] & 0xffff_f000 != 0xe28c_c000
        || words[2] & 0xffff_f000 != 0xe5bc_f000
    {
        return None;
    }
    let immediate = |word: u32| (word & 0xff).rotate_right(((word >> 8) & 15) * 2);
    Some(
        address
            .wrapping_add(8)
            .wrapping_add(immediate(words[0]))
            .wrapping_add(immediate(words[1]))
            .wrapping_add(words[2] & 0xfff),
    )
}
