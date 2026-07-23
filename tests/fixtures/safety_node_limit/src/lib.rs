pub fn root(pointer: *const u8) -> u8 {
    middle(pointer)
}

fn middle(pointer: *const u8) -> u8 {
    deeper(pointer)
}

fn deeper(pointer: *const u8) -> u8 {
    unsafe_leaf(pointer)
}

fn unsafe_leaf(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}

/// # Safety
///
/// This boundary owns the safety effects in its descendants.
fn documented_boundary(pointer: *const u8) -> u8 {
    middle(pointer)
}

pub fn bounded_root(pointer: *const u8) -> u8 {
    // SAFETY: documented_boundary owns its internal safety effects.
    documented_boundary(pointer)
}
