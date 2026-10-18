#[inline(never)]
fn add(a: i32, b: i32) -> i32 { a + b }

#[inline(never)]
fn twice(x: i32) -> i32 { add(x, x) }

fn main() { println!("{}", twice(21)); }
