/// # Panics
/// Panics when `flag` is false.
pub fn documented_contract(flag: bool) {
    assert!(flag);
}

pub fn undocumented_bug() {
    panic!("not documented");
}
