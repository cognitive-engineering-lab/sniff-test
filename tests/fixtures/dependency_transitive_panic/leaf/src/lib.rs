/// # Panics
/// leaf panics if `flag` is true
pub fn leaf(flag: bool) {
    assert!(flag, "leaf expected a set flag");
}
