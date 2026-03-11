#[sniff_tool::check_panics]
fn main() {
    let panic = || panic!();
    let dont_panic = || 0;
    let might_panic: fn() -> i32 = if 0 == 0 { panic } else { dont_panic };
    calls_f(might_panic);
}

// FALSE NEGATIVE: here, the closures get coerced into function pointers, so all we can see is
// that `calls_f` is called with `fn() -> i32` as a generic.
//
// Based on our discussion from last time, it seems like the best way to handle this is by warning the
// user we couldn't follow this indirection rather than doing some complicated function pointer analysis.
// TODO: for now just give a warning with fn pointers
fn calls_f(f: impl Fn() -> i32) -> i32 {
    f()
}

// NOTE: this can also happen bc of explicit coercion to a fn pointer.
fn main2() {
    let panic: fn() -> i32 = || panic!();
    calls_f(panic);
}
