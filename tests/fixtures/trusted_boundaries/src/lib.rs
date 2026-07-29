pub fn trusted_without_docs(flag: bool) {
    trusted_helper(flag);
}

pub fn trusted_with_docs(flag: bool) {
    trusted_doc_helper(flag);
}

fn trusted_helper(flag: bool) {
    assert!(flag);
    unsafe { unsafe_helper() }
}

/// # Panics
/// Panics when `flag` is false.
fn trusted_doc_helper(flag: bool) {
    assert!(flag);
}

unsafe fn unsafe_helper() {}

pub fn trusted_through_fn_pointer(flag: bool, unknown: fn(bool)) {
    let helper: fn(bool) = if flag { trusted_helper } else { unknown };
    helper(flag);
}

pub fn trusted_unsafe_without_docs() {
    unsafe { unsafe_helper() }
}

pub fn trusted_unsafe_through_fn_pointer(use_trusted: bool, unknown: unsafe fn()) {
    let helper: unsafe fn() = if use_trusted { unsafe_helper } else { unknown };
    unsafe { helper() }
}
