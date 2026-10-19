// L7 — Rust: mangled names and the Option/panic path.
// Expected: mangled names are demangled into readable form; the unwrap path remains.
#[inline(never)]
fn add(a: i32, b: i32) -> i32 { a + b }

#[inline(never)]
fn divmod(a: i32, b: i32) -> (i32, i32) { (a / b, a % b) }

#[inline(never)]
fn pick(v: Option<i32>) -> i32 { v.unwrap_or(-1) }

fn main() {
    println!("{}", add(1, 2));
    let _ = divmod(7, 3);
    let _ = pick(Some(3));
}
