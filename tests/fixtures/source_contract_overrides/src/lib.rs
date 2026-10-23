pub fn selected_panic(flag: bool) {
    assert!(flag, "selected panic");
}

pub fn adjacent_panic(flag: bool) {
    assert!(flag, "adjacent panic");
}

pub fn caller(flag: bool) {
    selected_panic(flag);
    adjacent_panic(flag);
    source_contract_dependency::dependency_panic(flag);
}

pub mod trait_api;
pub mod generic_effects;

pub fn justified(flag: bool) {
    // PANIC:
    // - selected: this caller has checked the flag.
    selected_panic(flag);
    // PANIC:
    // - dependency: this caller has checked the flag.
    source_contract_dependency::dependency_panic(flag);
}
