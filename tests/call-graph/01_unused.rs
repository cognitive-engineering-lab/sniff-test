#[sniff_tool::check_panics]
fn main() {
    let panic = || panic!();
    doesnt_call_f(panic);
}

// FALSE POSITIVE: we'd see that line 4 calls to `doesnt_call_f` with the closure@..:15 as a generic
// and conservatively flag that it could call that closure and panic.
//
// This is similar to (what is technically) false positives we'd get for things like [Iterator::map](https://doc.rust-lang.org/src/core/iter/traits/iterator.rs.html#777-780)
fn doesnt_call_f(f: impl Fn() -> i32) -> i32 {
    0
}

// so with .map.collect, we'd have issue with both map and collect
// comment to say something like "ignore this call edge"
// more complex analysis could tell in this case
