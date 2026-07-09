/// # Panics
///
/// Panics when `flag` is false.
pub fn checked(flag: bool) {
    assert!(flag, "flag must be set");
}
