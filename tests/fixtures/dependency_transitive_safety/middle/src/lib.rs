/// # Safety
/// `pointer` must be valid to read an initialized byte.
pub fn undocumented_leaf(pointer: *const u8) -> u8 {
    dependency_transitive_safety_leaf::undocumented_leaf(pointer)
}

/// # Safety
/// `pointer` must be valid to read an initialized byte.
pub fn documented_leaf(pointer: *const u8) -> u8 {
    dependency_transitive_safety_leaf::documented_leaf(pointer)
}

/// # Safety
/// `pointer` must be valid to read an initialized byte.
pub fn justified_leaf(pointer: *const u8) -> u8 {
    // SAFETY: the caller guarantees a valid pointer to an initialized byte.
    dependency_transitive_safety_leaf::documented_leaf(pointer)
}
