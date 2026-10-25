use super::*;

#[test]
fn header_prototypes_print_arguments_results_and_record_fields() {
    for arch in ["arm64", "x86_64"] {
        let mut binary =
            Binary::open(&common::fixtures_dir().join(format!("type_library_{arch}"))).unwrap();
        let address = binary.find("library_group").unwrap().addr;
        let group = binary.decompile(address, None, None).unwrap();
        assert!(group.contains("struct group *"), "{group}");
        assert!(group.contains("->gr_gid"), "{group}");
        assert!(group.contains("getgrgid_r(7,"), "{group}");
        let code = format!(
            "struct group;\nint getgrgid_r(unsigned int, struct group *, char *, size_t, struct group **);\n{group}"
        );
        syntax::run_printed(
            &code,
            "int getgrgid_r(unsigned int gid, struct group *entry, char *buffer, size_t size, struct group **result) { entry->gr_gid = (gid == 7 && !buffer && !size && !result) ? 0x80000001U : 0; return 0; }",
            "struct group entry = {0}; return (uint32_t)library_group(&entry) != 0x80000001U;",
        );
        let address = binary.find("library_group_at").unwrap().addr;
        let indexed = binary.decompile(address, None, None).unwrap();
        assert!(indexed.contains(".gr_gid"), "{indexed}");
        let combined = velk::render::combine(&format!("{group}{indexed}"));
        assert_eq!(combined.matches("struct group {").count(), 1, "{combined}");
        syntax::run_printed(
            &format!(
                "struct group;\nint getgrgid_r(unsigned int, struct group *, char *, size_t, struct group **);\n{combined}"
            ),
            "int getgrgid_r(unsigned int gid, struct group *entry, char *buffer, size_t size, struct group **result) { entry->gr_gid = gid; return buffer || size || result; }",
            "struct group entries[2] = {0}; entries[1].gr_gid = 0xfedcba98U; return (uint32_t)library_group(entries) != 7 || (uint32_t)library_group_at(entries, 0) != 7 || (uint32_t)library_group_at(entries, 1) != 0xfedcba98U;",
        );
        let address = binary.find("library_wide_length").unwrap().addr;
        let wide = binary.decompile(address, None, None).unwrap();
        assert!(wide.contains("const int *"), "{wide}");
        assert!(wide.contains("return wcslen("), "{wide}");
        assert!(wide.contains("size_t library_wide_length("), "{wide}");
        syntax::run_printed(
            &format!("size_t wcslen(const int *);\n{wide}"),
            "size_t wcslen(const int *text) { return UINT64_C(0x100000000) + (unsigned int)text[0]; }",
            "int text[] = {37, 0}; return library_wide_length(text) != UINT64_C(0x100000025);",
        );
    }
}
