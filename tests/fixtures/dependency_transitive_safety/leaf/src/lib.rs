pub fn undocumented_leaf(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}

/// # Safety
/// `pointer` must be valid to read an initialized byte.
pub fn documented_leaf(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}
