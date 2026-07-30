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

unsafe fn perform() {}

macro_rules! perform_once {
    () => {{
        // SAFETY: this fixture's operation has no additional requirements.
        unsafe { perform() }
    }};
}

pub fn reused_macro_marker() {
    perform_once!();
    perform_once!();
}

macro_rules! nested_perform_once {
    () => {{
        perform_once!()
    }};
}

pub fn reused_nested_macro_marker() {
    nested_perform_once!();
    nested_perform_once!();
}

macro_rules! perform_twice_via_marked_inner_macro {
    () => {{
        perform_once!();
        perform_once!();
    }};
}

pub fn distinct_inner_markers_within_one_outer_macro_expansion() {
    perform_twice_via_marked_inner_macro!();
}

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

macro_rules! perform_once_without_marker {
    () => {{
        unsafe { perform() }
    }};
}

macro_rules! call_perform_twice_without_marker {
    () => {{
        perform_once_without_marker!();
        perform_once_without_marker!();
    }};
}

pub fn reused_caller_marker_for_macro_expansion() {
    // SAFETY: this fixture's operations have no additional requirements.
    call_perform_twice_without_marker!();
}
