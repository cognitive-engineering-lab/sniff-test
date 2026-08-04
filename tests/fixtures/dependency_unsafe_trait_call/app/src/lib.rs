use dependency_unsafe_trait_call_dep::Action;

struct Local;

impl Action for Local {
    unsafe fn apply() {}

    fn may_panic() {
        panic!("implementation panic");
    }
}

pub fn caller() {
    dependency_unsafe_trait_call_dep::invoke::<Local>();
}

pub fn panic_caller() {
    dependency_unsafe_trait_call_dep::invoke_panic::<Local>();
}

pub fn nested_caller() {
    dependency_unsafe_trait_call_dep::invoke_nested::<Local>();
}

pub fn nested_panic_caller() {
    dependency_unsafe_trait_call_dep::invoke_panic_nested::<Local>();
}
