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
