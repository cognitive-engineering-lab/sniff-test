pub fn undocumented_leaf() -> u8 {
    let byte = 7;
    dependency_transitive_safety_middle::undocumented_leaf(&byte)
}

pub fn documented_leaf() -> u8 {
    let byte = 7;
    dependency_transitive_safety_middle::documented_leaf(&byte)
}

pub fn justified_leaf() -> u8 {
    let byte = 7;
    dependency_transitive_safety_middle::justified_leaf(&byte)
}

pub fn justified_app() -> u8 {
    let byte = 7;
    // SAFETY: the pointer comes from a live reference to an initialized byte.
    dependency_transitive_safety_middle::documented_leaf(&byte)
}
