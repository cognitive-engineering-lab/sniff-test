/// # Safety
///
/// Requirements:
/// - initialized: global state must be initialized
/// - exclusive: no other thread may access the global state
pub fn requires_initialized_exclusive_state() {}

pub fn misses_both_requirements() {
    requires_initialized_exclusive_state();
}

fn shared_effect() {
    requires_initialized_exclusive_state();
}

fn satisfies_initialized() {
    // SAFETY:
    // - initialized: this path initialized the global state.
    shared_effect();
}

fn satisfies_exclusive() {
    // SAFETY:
    // - exclusive: this path has exclusive access to the global state.
    shared_effect();
}

pub fn complementary_paths() {
    satisfies_initialized();
    satisfies_exclusive();
}
