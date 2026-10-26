//! The shared export-entry limit, independent of the parser producing entries.

#[kani::proof]
fn export_trie_limit() {
    let value: u64 = kani::any();
    let index: usize = kani::any();
    let mut exports = crate::loader::limited_exports(std::iter::repeat(value));
    assert_eq!(
        exports.nth(index),
        (index < crate::loader::MAX_EXPORTS).then_some(value)
    );
    if index >= crate::loader::MAX_EXPORTS - 1 {
        assert_eq!(exports.next(), None);
    } else {
        assert_eq!(exports.next(), Some(value));
    }
}
