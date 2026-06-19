pub fn trusted_without_docs(flag: bool) {
    trusted_helper(flag);
}

pub fn trusted_with_docs(flag: bool) {
    trusted_doc_helper(flag);
}

fn trusted_helper(flag: bool) {
    assert!(flag);
}

/// # Panics
/// Panics when `flag` is false.
fn trusted_doc_helper(flag: bool) {
    assert!(flag);
}
