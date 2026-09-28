pub fn map(f: impl Fn(usize) -> usize) -> usize {
    f(1)
}

/// # Panics
/// Panics when `value` is zero.
pub fn documented(value: usize) -> usize {
    assert_ne!(value, 0);
    value
}
