pub trait Action {
    /// # Safety
    ///
    /// Requirements:
    /// - invariant: the private test invariant must hold.
    unsafe fn apply();
}

/// # Safety
///
/// Requirements:
/// - state: the first dependency invariant must hold.
/// - state: the second dependency invariant must hold.
pub fn ambiguous_obligation() {}

#[inline(never)]
pub fn invoke<T: Action>() {
    // SAFETY:
    // - invariant: implementations uphold the trait's private test invariant.
    unsafe {
        T::apply();
    }
}

#[inline(never)]
pub fn invoke_unjustified<T: Action>() {
    unsafe {
        T::apply();
    }
}
