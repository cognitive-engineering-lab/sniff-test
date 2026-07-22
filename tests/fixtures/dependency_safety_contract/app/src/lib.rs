pub fn reaches_two_effects(pointer: *const u8) -> u8 {
    dependency_safety_contract::two_reads(pointer)
}

pub fn justifies_dependency_effects(pointer: *const u8) -> u8 {
    // SAFETY: the caller guarantees that both bytes are readable.
    dependency_safety_contract::two_reads(pointer)
}

pub fn reaches_missing_requirement() {
    dependency_safety_contract::misses_named_requirement();
}

pub fn unnamed_marker_does_not_satisfy_cached_requirement() {
    // SAFETY: this does not name the dependency's `initialized` requirement.
    dependency_safety_contract::misses_named_requirement();
}

pub fn named_marker_satisfies_cached_requirement() {
    // SAFETY:
    // - initialized: the application initialized the global state.
    dependency_safety_contract::misses_named_requirement();
}
