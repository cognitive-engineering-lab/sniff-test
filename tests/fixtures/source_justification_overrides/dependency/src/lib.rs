pub fn selected() {
    assert!(std::hint::black_box(true), "selected dependency panic");
}

pub fn control() {
    assert!(std::hint::black_box(true), "control dependency panic");
}

/// # Panics
/// - valid: the input must be validated.
/// - bounded: the input must be bounded.
pub fn contract() {}
