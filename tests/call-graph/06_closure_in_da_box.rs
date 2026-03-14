#[sniff_tool::check_panics]
fn main() {
    let panic_closure = || panic!();
    let might_panic = || panic_closure();
    calls_f(Box::new(might_panic));
}

fn calls_f(f: impl std::ops::Deref<Target = impl Fn() -> i32>) -> i32 {
    f()
}
