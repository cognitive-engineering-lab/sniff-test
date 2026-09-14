fn calls_once<F: FnOnce()>(function: F) {
    function()
}

fn calls_fn<F: Fn()>(function: F) {
    function()
}

pub fn no_capture_panics() {
    let panic = || panic!("test");
    calls_once(panic);
}

pub fn consuming_capture_panics() {
    let owned = String::from("owned capture");
    calls_once(move || {
        drop(owned);
        panic!("consuming closure");
    });
}

pub fn mutable_capture_panics() {
    let mut owned = String::from("mutable capture");
    calls_once(move || {
        owned.clear();
        panic!("mutable closure");
    });
}

pub fn quiet_closure() {
    calls_once(|| ());
}

pub fn fn_control_panics() {
    calls_fn(|| panic!("Fn control"));
}

pub fn unsafe_closure() {
    calls_once(|| {
        let value = 42;
        let pointer = &raw const value;
        unsafe {
            std::hint::black_box(*pointer);
        }
    });
}

/// # Panics
/// The caller must justify this documented panic requirement.
fn documented_panic() {}

pub fn documented_closure() {
    calls_once(|| documented_panic());
}
