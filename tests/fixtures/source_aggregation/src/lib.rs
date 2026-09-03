fn shared_panic_source() {
    panic!("shared source");
}

pub fn first_api() {
    shared_panic_source();
}

pub fn second_api() {
    shared_panic_source();
}
