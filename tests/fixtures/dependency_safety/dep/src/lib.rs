pub fn read_byte(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}

/// # Safety
///
/// `pointer` must be valid to read for one byte.
unsafe fn documented_read(pointer: *const u8) -> u8 {
    // SAFETY: delegated to the caller.
    unsafe { *pointer }
}

pub fn read_documented(pointer: *const u8) -> u8 {
    unsafe { documented_read(pointer) }
}
