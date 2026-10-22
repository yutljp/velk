use std::collections::HashMap;

#[derive(Default)]
pub struct Symbols {
    pub functions: HashMap<u64, String>,
    pub import_slots: HashMap<u64, String>,
    pub data: HashMap<u64, String>,
}
