use std::ptr::NonNull;

/// # Safety
///
/// The caller must satisfy all listed requirements.
///
/// Requirements:
///
/// - valid_ptr: pointer must be non-null.
/// - initialized: pointer must reference initialized memory.
pub unsafe fn read_byte(ptr: *const u8) -> u8 {
    // SAFETY:
    // - valid_ptr: delegated to the caller.
    // - initialized: delegated to the caller.
    unsafe { *ptr }
}

/// # Safety
///
/// The caller must satisfy all listed requirements.
///
/// Requirements:
///
/// - valid_ptr: pointer must be non-null.
/// - writable: pointer must reference writable memory.
pub unsafe fn write_byte(ptr: *mut u8, value: u8) {
    // SAFETY:
    // - valid_ptr: delegated to the caller.
    // - writable: delegated to the caller.
    unsafe { *ptr = value }
}

pub unsafe fn undocumented_public(_ptr: *const u8) -> u8 {
    0
}

unsafe fn private_unsafe_no_docs() {}

pub fn satisfied_by_block_and_call() -> u8 {
    let mut byte = 7;
    let ptr = NonNull::from(&mut byte);

    // SAFETY:
    // - valid_ptr: NonNull was created from a live mutable reference.
    unsafe {
        // SAFETY:
        // - initialized: `byte` was initialized above.
        read_byte(ptr.as_ptr())
    }
}

pub fn block_scope_covers_multiple_calls() -> u8 {
    let mut byte = 7;
    let ptr = NonNull::from(&mut byte);

    // SAFETY:
    // - valid_ptr: NonNull was created from a live mutable reference.
    // - writable: `byte` is uniquely borrowed for this block.
    unsafe {
        // SAFETY:
        // - initialized: `byte` was initialized above.
        let read = read_byte(ptr.as_ptr());
        write_byte(ptr.as_ptr(), read.saturating_add(1));
    }

    byte
}

pub fn missing_requirement() -> u8 {
    let mut byte = 7;
    let ptr = NonNull::from(&mut byte);

    // SAFETY:
    // - valid_ptr: NonNull was created from a live mutable reference.
    unsafe { read_byte(ptr.as_ptr()) }
}

pub fn safety_marker_boundary_missing_requirements() -> u8 {
    let mut byte = 7;
    let ptr = NonNull::from(&mut byte);

    // SAFETY:
    // PANIC: this starts a different marker block.
    // - valid_ptr: this must not satisfy the safety contract.
    // - initialized: this must not satisfy the safety contract.
    unsafe { read_byte(ptr.as_ptr()) }
}

pub fn missing_justification() {
    unsafe { private_unsafe_no_docs() }
}

pub fn unsafe_fn_pointer_with_justification() {
    let function: unsafe fn() = private_unsafe_no_docs;

    // SAFETY: private function has no caller-visible requirements.
    unsafe { function() }
}

pub fn unsafe_fn_pointer_missing_justification() {
    let function: unsafe fn() = private_unsafe_no_docs;

    unsafe { function() }
}

pub trait UnsafeGreeter {
    /// # Safety
    ///
    /// Requirements:
    ///
    /// - valid_ptr: pointer must be non-null.
    unsafe fn greet(&self, ptr: *const u8);
}

pub struct Greeter;

impl UnsafeGreeter for Greeter {
    /// # Safety
    ///
    /// Requirements:
    ///
    /// - valid_ptr: pointer must be non-null.
    unsafe fn greet(&self, _ptr: *const u8) {}
}

pub fn generic_unsafe_trait_method_satisfied<T: UnsafeGreeter>(greeter: T) {
    let byte = 7;
    let ptr = &raw const byte;

    // SAFETY:
    // - valid_ptr: pointer was created from a live reference.
    unsafe { greeter.greet(ptr) }
}

pub fn generic_unsafe_trait_method_missing<T: UnsafeGreeter>(greeter: T) {
    let byte = 7;
    let ptr = &raw const byte;

    unsafe { greeter.greet(ptr) }
}

/// # Safety
///
/// Requirements:
///
/// - valid_ptr: pointer must be non-null.
pub fn safe_documented_contract(_ptr: *const u8) {}

pub fn safe_undocumented_contract() {}

pub fn configured_safety_obligation_satisfied() {
    let byte = 7;
    let ptr = &raw const byte;

    // SAFETY:
    // - valid_ptr: pointer was created from a live reference.
    safe_documented_contract(ptr);
}

pub fn configured_safety_obligation_missing_requirement() {
    let byte = 7;
    let ptr = &raw const byte;

    safe_documented_contract(ptr);
}

pub fn configured_safety_obligation_missing_justification() {
    safe_undocumented_contract();
}

/// # Safety
///
/// Requirements:
///
/// - ready: the caller must establish the target-specific precondition.
unsafe fn documented_pointer_target() {}

pub fn unsafe_fn_pointer_named_requirement_satisfied() {
    let function: unsafe fn() = documented_pointer_target;

    // SAFETY: the erased pointer is constrained to the documented target.
    // - ready: the target-specific precondition is established.
    unsafe { function() }
}

pub fn unsafe_fn_pointer_named_requirement_missing() {
    let function: unsafe fn() = documented_pointer_target;

    // SAFETY: the erased pointer call is intentional, but `ready` is not established.
    unsafe { function() }
}

pub fn unknown_unsafe_fn_pointer(function: unsafe fn()) {
    unsafe { function() }
}

pub fn safe_obligation_through_unsafe_pointer_satisfied() {
    let byte = 7;
    let ptr = &raw const byte;

    // SAFETY: the erased pointer is constrained to the documented target.
    // - valid_ptr: pointer was created from a live reference.
    unsafe {
        let function: unsafe fn(*const u8) = safe_documented_contract;
        function(ptr);
    }
}
