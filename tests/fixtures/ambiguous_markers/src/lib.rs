/// # Panics
///
/// Panics when `denominator` is zero.
pub fn ratio(total: usize, denominator: usize) -> usize {
    total / denominator
}

pub fn shared_block_marker(a: usize, b: usize, denominator: usize) -> usize {
    // PANIC: all denominators in this guarded block are nonzero.
    {
        let first = ratio(a, denominator);
        let second = ratio(b, denominator);
        first.saturating_add(second)
    }
}
