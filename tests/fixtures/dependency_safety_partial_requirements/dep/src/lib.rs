/// # Safety
///
/// Requirements:
/// - initialized: global state must be initialized
/// - aligned: the shared buffer must be aligned
pub fn requires_both_invariants() {}

pub fn misses_both_requirements() {
    requires_both_invariants();
}
