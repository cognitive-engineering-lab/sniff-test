pub trait Action {
    /// # Safety
    ///
    /// Requirements:
    /// - invariant: the private test invariant must hold.
    unsafe fn apply();

    /// # Panics
    ///
    /// Requirements:
    /// - permitted: the caller permits this implementation to panic.
    fn may_panic();
}

#[inline(never)]
pub fn invoke<T: Action>() {
    // SAFETY:
    // - invariant: implementations uphold the trait's private test invariant.
    unsafe {
        T::apply();
    }
}

#[inline(never)]
pub fn invoke_panic<T: Action>() {
    // PANIC:
    // - permitted: this test path explicitly permits the implementation panic.
    T::may_panic();
}

#[inline(never)]
pub fn invoke_nested<T: Action>() {
    let call = || {
        // SAFETY:
        // - invariant: implementations uphold the trait's private test invariant.
        unsafe {
            T::apply();
        }
    };
    call();
}

#[inline(never)]
pub fn invoke_panic_nested<T: Action>() {
    let call = || {
        // PANIC:
        // - permitted: this test path explicitly permits the implementation panic.
        T::may_panic();
    };
    call();
}

struct DependencyAction;

impl Action for DependencyAction {
    unsafe fn apply() {}

    fn may_panic() {
        panic!("dependency implementation panic");
    }
}

pub fn instantiate_nested_bodies() {
    invoke_nested::<DependencyAction>();
    invoke_panic_nested::<DependencyAction>();
}
