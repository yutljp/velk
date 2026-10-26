fn main() {
    for path in [
        "signatures/x86_64.bin.gz",
        "signatures/aarch64.bin.gz",
        "signatures/i386.bin.gz",
        "signatures/arm32.bin.gz",
    ] {
        println!("cargo::rerun-if-changed={path}");
    }
}
