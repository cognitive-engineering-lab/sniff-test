pub fn read_dependency(pointer: *const u8) -> u8 {
    dependency_safety::read_byte(pointer)
}

/// # Safety
/// The pointer must be valid to read.
pub fn documented_read_dependency(pointer: *const u8) -> u8 {
    dependency_safety::read_byte(pointer)
}
