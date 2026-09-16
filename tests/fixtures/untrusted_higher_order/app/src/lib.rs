//! Application library for the untrusted higher-order fixture.
use trusted::consume_maybe_untrusted_closure;
use trusted::BlanketFromUntrustedParty;

struct Bar;
impl BlanketFromUntrustedParty for Bar {
    fn maybe_untrusted_impl(&self) {
        panic!("boom");
    }
}

pub fn higher_order_closure_effect() {
    let boom = || { panic!("boom"); };
    consume_maybe_untrusted_closure(boom);
}

pub fn higher_order_function_impl_effect() {
    let bar = Bar;
    BlanketFromUntrustedParty::boom(&bar);
}

impl trusted::DocumentedBlanket for Bar {
    fn maybe_untrusted_impl(&self) {
        panic!("documented trait callback");
    }
}

pub fn documented_closure_effect_is_discharged() {
    // PANIC: This callback deliberately panics; its contract is accepted.
    trusted::consume_documented_closure(|| panic!("documented callback"));
}

pub fn documented_trait_effect_is_discharged() {
    // PANIC: This implementer's panic is accepted under the method contract.
    trusted::DocumentedBlanket::boom(&Bar);
}

pub fn option_map_callback_effect() {
    Some(1).map(|_| panic!("Option::map callback"));
}

pub fn option_and_then_callback_effect() {
    Some(1).and_then(|_| -> Option<u8> { panic!("Option::and_then callback") });
}

pub fn trusted_std_dependencies_are_discharged() {
    let mut map = std::collections::HashMap::new();
    map.insert(1_u8, 2_u8);
}
