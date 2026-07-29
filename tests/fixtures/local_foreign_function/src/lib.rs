unsafe extern "C" {
    fn foreign_function();
}

pub fn calls_local_foreign_function() {
    // SAFETY: this fixture is only compiled with `cargo check`, so the symbol
    // is never linked or invoked.
    unsafe { foreign_function() }
}
