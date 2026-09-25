pub fn dependency_effects_through_a_are_trusted() {
    trusted_a::dependency_effect();
}

pub fn a_callback_through_b_is_trusted() {
    trusted_a::own_callback();
}

pub fn direct_dependency_effect_is_untrusted() {
    dep_b::dependency_effect();
}

pub fn app_callback_through_b_is_untrusted() {
    trusted_a::forward_callback(|| panic!("application callback"));
}

pub fn callback_reentering_dependency_is_untrusted() {
    trusted_a::forward_callback(|| dep_c::panic_effect());
}

pub fn safety_through_a_is_trusted() {
    trusted_a::safety_effect();
}

pub fn direct_dependency_safety_is_untrusted() {
    dep_b::safety_effect();
}

pub fn app_safety_callback_is_untrusted() {
    trusted_a::forward_callback(|| {
        let pointer = std::ptr::null::<u8>();
        unsafe { let _value = *pointer; }
    });
}

pub fn documented_callback_is_discharged() {
    // PANIC: Deliberate callback panic covered by the callee contract.
    trusted_a::documented_callback(|| panic!("documented application callback"));
}

pub fn documented_safety_callback_is_discharged() {
    // SAFETY: The callback's operations are accepted under the callee contract.
    trusted_a::documented_safety_callback(|| {
        let pointer = std::ptr::null::<u8>();
        unsafe { let _value = *pointer; }
    });
}

pub fn implicit_std_dependencies_through_a_are_trusted() {
    trusted_a::std_dependency_effect();
}
