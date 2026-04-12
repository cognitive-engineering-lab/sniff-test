#[sniff_tool::check_panics]
fn main() {
    let panic_closure = || panic!();
    let might_panic = || panic_closure();
    calls_f(might_panic);
}

// TRUE POSITIVE: we can detect this case because, although the specific closure generic for `calls_f`
// (might_panic) doesn't panic directly, its captures are represented as function arguments at the MIR level.
// Since we know this closure captures (has an argument of the type of) this specific closure that can panic
// we can determine the check should fail this way.
// TODO: discuss to double check this is doing what I think it is in the MIR
fn calls_f(f: impl Fn() -> i32) -> i32 {
    f()
}
// TODO: use the monomorphization of call to detect the capture
