pub fn invoke(callback: impl Fn()) {
    callback();
}

/// # Panics
/// Always panics.
pub fn panic_transform() {
    panic!("trusted callback selected by an untrusted consumer");
}
