pub fn raw_panic() {
    panic!("raw cached panic");
}

pub fn two_raw_panics(left: bool, right: bool) {
    assert!(left, "left cached panic");
    assert!(right, "right cached panic");
}

/// # Panics
///
/// Requirements:
/// - nonzero: the value must not be zero
pub fn requires_nonzero() {}

pub fn misses_named_requirement() {
    requires_nonzero();
}
