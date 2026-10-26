use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

fn main() -> std::io::Result<()> {
    let input = std::env::args().nth(1).unwrap_or_else(|| "42".to_owned());
    let mut values: Vec<u64> = (0..128).map(|i| i ^ 53).collect();
    values.sort_unstable();
    let mut map = HashMap::new();
    let mut tree = BTreeMap::new();
    let mut set = HashSet::new();
    let mut queue = VecDeque::new();
    for value in values {
        map.insert(value.to_string(), value);
        tree.insert(value, value * 3);
        set.insert(value);
        queue.push_back(value);
    }
    let parsed = input.parse::<u64>().unwrap_or_default();
    let shared = Arc::new(Mutex::new(parsed));
    let copy = Arc::clone(&shared);
    std::thread::spawn(move || *copy.lock().unwrap() += 1).join().unwrap();
    let path = PathBuf::from("a").join(&input);
    let mut cursor = std::io::Cursor::new(input.as_bytes());
    let mut bytes = Vec::new();
    cursor.read_to_end(&mut bytes)?;
    let text = format!("{}:{}:{}:{:?}:{}:{}", map.len(), tree.len(), set.len(), path, queue.len(), *shared.lock().unwrap());
    std::io::stdout().lock().write_all(text.as_bytes())
}
