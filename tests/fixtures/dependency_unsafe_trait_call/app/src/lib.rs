use dependency_unsafe_trait_call_dep::Action;

struct Local;

impl Action for Local {
    unsafe fn apply() {}
}

pub fn justified_caller() {
    dependency_unsafe_trait_call_dep::invoke::<Local>();
}

pub fn unjustified_caller() {
    dependency_unsafe_trait_call_dep::invoke_unjustified::<Local>();
}
