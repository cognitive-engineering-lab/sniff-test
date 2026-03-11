#[sniff_tool::check_panics]
fn main() {
    let panic = || panic!();
    calls_f(panic);
}

// TRUE POSITIVE: we'd catch this, as line 4 will call to a monomorphized
// version of `calls_f` that has closure@..:15 as its generic
fn calls_f(f: impl Fn() -> i32) -> i32 {
    f()
}

// For completeness, the above is exactly equivalent to this as well
// fn calls_f<F: Fn() -> i32>(f: F) -> i32 {
//     f()
// }
