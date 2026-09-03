use std::ptr::NonNull;

/// # Safety
///
/// Requirements:
///
/// - valid_ptr: pointer must be non-null.
/// - valid_ptr: pointer must reference initialized memory.
pub unsafe fn read_duplicate(ptr: *const u8) -> u8 {
    // SAFETY: delegated to the caller.
    unsafe { *ptr }
}

pub fn duplicate_safety_marker() -> u8 {
    let byte = 7;
    let ptr = NonNull::from(&byte);

    // SAFETY:
    // - valid_ptr: pointer was created from a live reference.
    unsafe { read_duplicate(ptr.as_ptr()) }
}

/// # Safety
///
/// The caller must uphold this fixture's synthetic safety invariant.
unsafe fn perform() {}

macro_rules! perform_twice_without_marker {
    () => {{
        unsafe { perform() };
        unsafe { perform() };
    }};
}

macro_rules! call_perform_twice_with_one_marker {
    () => {{
        // SAFETY: this fixture's operations have no additional requirements.
        perform_twice_without_marker!()
    }};
}

pub fn reused_marker_within_one_macro_expansion() {
    call_perform_twice_with_one_marker!();
}

fn read_copy<T: Copy>(value: &T) -> T {
    // SAFETY: `value` is a valid, initialized `T`.
    unsafe { std::ptr::read(value) }
}

pub fn reused_marker_across_generic_instances() {
    let byte = 7_u8;
    let word = 11_u16;
    let _ = read_copy(&byte);
    let _ = read_copy(&word);
}

/// # Safety
///
/// Requirements:
///
/// - initialized: shared state must be initialized.
/// - exclusive: no concurrent access is allowed.
pub fn safe_obligation() {}

macro_rules! call_safe_obligation_twice {
    () => {{
        safe_obligation();
        safe_obligation();
    }};
}

macro_rules! call_safe_obligation_twice_with_partial_marker {
    () => {{
        // SAFETY:
        // - initialized: this fixture initializes the shared state.
        call_safe_obligation_twice!()
    }};
}

pub fn reused_partial_marker_for_safe_obligations() {
    call_safe_obligation_twice_with_partial_marker!();
}

#[allow(unused_unsafe)]
pub fn reused_partial_marker_for_safe_obligations_inside_unsafe_block() {
    // SAFETY:
    // - initialized: this fixture initializes the shared state.
    unsafe {
        safe_obligation();
        safe_obligation();
    }
}
