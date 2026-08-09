use dependency_generic_local_impl::Action;

struct Local;

impl Action for Local {
    fn apply(flag: bool) {
        assert!(flag, "workspace implementation expected a set flag");
    }
}

pub fn caller(flag: bool) {
    dependency_generic_local_impl::invoke::<Local>(flag);
}
