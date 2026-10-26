use function_item_trust_dep::{invoke, panic_transform};

pub fn direct_function_item_from_untrusted_consumer() {
    invoke(panic_transform);
}
