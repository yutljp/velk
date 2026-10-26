use std::path::PathBuf;
use std::sync::OnceLock;

pub fn path(bytes: &[u8]) -> &'static PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    let path = PATH.get_or_init(|| {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/fuzz-inputs");
        std::fs::create_dir_all(&directory).expect("create fuzz input directory");
        directory.join(format!("{}.bin", std::process::id()))
    });
    std::fs::write(path, bytes).expect("write fuzz input");
    path
}
