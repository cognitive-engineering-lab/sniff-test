/// # Safety
///
/// Requirements:
/// - initialized: global state must be initialized
/// - exclusive: no other thread may access the global state
pub fn requires_initialized_exclusive_state() {}

pub fn misses_both_requirements() {
    requires_initialized_exclusive_state();
}
