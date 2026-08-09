/// # Panics
/// Panics when `flag` is false.
pub fn documented_contract(flag: bool) {
    assert!(flag);
}

pub fn reaches_documented_contract(flag: bool) {
    documented_contract(flag);
}
