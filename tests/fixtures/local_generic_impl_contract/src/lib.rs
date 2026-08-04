trait Action {
    /// # Safety
    ///
    /// Requirements:
    /// - invariant: the caller preserves the trait invariant.
    unsafe fn apply();
}

struct Wrapper<T>(core::marker::PhantomData<T>);

impl<T> Action for Wrapper<T> {
    unsafe fn apply() {}
}

#[inline(never)]
fn invoke_statically_selected_impl<T>() {
    // SAFETY: the selected impl has no documented requirements.
    unsafe {
        Wrapper::<T>::apply();
    }
}

pub fn caller() {
    invoke_statically_selected_impl::<u8>();
}
