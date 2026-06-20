pub fn safe_ratio(total: usize, denominator: usize) -> usize {
    // PANIC: caller guarantees denominator is nonzero.
    // This invariant is enforced by the public constructor.
    total / denominator
}

pub fn unsafe_ratio(total: usize, denominator: usize) -> usize {
    total / denominator
}

pub fn safe_call(flag: bool) {
    // PANIC: caller guarantees the helper precondition.
    helper(flag);
}

pub fn unsafe_call(flag: bool) {
    helper(flag);
}

fn helper(flag: bool) {
    assert!(flag);
}
