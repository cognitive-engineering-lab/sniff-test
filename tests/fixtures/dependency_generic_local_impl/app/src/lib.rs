use dependency_generic_local_impl::Action;

struct Local;

impl Action for Local {
    fn apply(flag: bool) {
        assert!(flag, "workspace implementation expected a set flag");
        let mut value = 0_u8;
        let pointer = &mut value as *mut u8;
        unsafe {
            *pointer = 1;
        }
    }
}

pub fn caller(flag: bool) {
    dependency_generic_local_impl::invoke::<Local>(flag);
}
