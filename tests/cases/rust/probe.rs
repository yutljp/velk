// L7 — Rust。マングル名の復元と Option/panic 経路。
// 期待: マングル名が読める形にデマングルされ、unwrap 経路が残る。
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
