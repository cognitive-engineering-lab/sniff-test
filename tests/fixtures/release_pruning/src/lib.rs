pub fn debug_only(flag: bool) {
    debug_assert!(flag);
}

pub fn checked_in_release(flag: bool) {
    assert!(flag);
}
