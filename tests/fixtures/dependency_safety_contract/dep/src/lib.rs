pub fn two_reads(pointer: *const u8) -> u8 {
    let first = unsafe { *pointer };
    let second = unsafe { *pointer };
    first + second
}

/// # Safety
///
/// Requirements:
/// - initialized: global state must be initialized
pub fn requires_initialized_state() {}

pub fn misses_named_requirement() {
    requires_initialized_state();
}
