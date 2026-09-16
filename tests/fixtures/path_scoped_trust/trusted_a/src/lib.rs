pub fn dependency_effect() {
    dep_b::dependency_effect();
}

pub fn own_callback() {
    dep_b::consume(|| panic!("trusted A callback"));
}

pub fn forward_callback(callback: impl Fn()) {
    dep_b::consume(callback);
}

pub fn safety_effect() {
    dep_b::safety_effect();
}

/// # Panics
/// Panics if the supplied callback panics.
pub fn documented_callback(callback: impl Fn()) {
    dep_b::consume(callback);
}

/// # Safety
/// The callback's unsafe operations must be valid.
pub fn documented_safety_callback(callback: impl Fn()) {
    dep_b::consume(callback);
}

pub fn std_dependency_effect() {
    let mut map = std::collections::HashMap::new();
    map.insert(1_u8, 2_u8);
}
