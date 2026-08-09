unsafe fn perform() {}

macro_rules! perform_once {
    () => {{
        // SAFETY: `perform` has no preconditions in this fixture.
        unsafe { perform() }
    }};
}

pub fn marked_expansions_are_justified() {
    perform_once!();
    perform_once!();
}

pub fn direct_call_requires_justification() {
    unsafe { perform() }
}
