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

macro_rules! call_unsafe_twice_without_marker {
    () => {{
        unsafe { unsafe_helper() };
        unsafe { unsafe_helper() };
    }};
}

macro_rules! call_unsafe_twice_with_one_marker {
    () => {{
        // SAFETY: this trusted implementation owns both internal operations.
        call_unsafe_twice_without_marker!()
    }};
}

pub fn trusted_marker_wrapper() {
    call_unsafe_twice_with_one_marker!();
}

struct PanickingWidget(bool);

impl PanickingWidget {
    /// # Panics
    ///
    /// Panics when the inner flag is false.
    fn risky(&self) -> bool {
        assert!(self.0);
        self.0
    }
}

fn trusted_comment_helper(widget: &PanickingWidget) -> bool {
    // PANIC: this trusted implementation establishes both preconditions.
    let results = (widget.risky(), widget.risky());
    results.0 && results.1
}

pub fn trusted_comment_wrapper() -> bool {
    trusted_comment_helper(&PanickingWidget(true))
}

pub fn trusted_unresolved_wrapper(callback: fn()) {
    callback();
}

pub fn untrusted_unresolved_wrapper(callback: fn()) {
    callback();
}
