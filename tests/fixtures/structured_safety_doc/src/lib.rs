pub fn foo() {
    // SAFETY: 
    // - req_1: justification
    // - req_2: justification
    unsafe {
        multi_safety_requirements_with_dash();
    }

    // SAFETY: 
    // - req_1: justification
    // - req_2: justification
    unsafe {
        multi_safety_requirements_with_asterisks();
    }

    // SAFETY: one-liner justification
    unsafe {
        multi_safety_requirements_with_asterisks_and_ident();
    }

}

pub fn complex_safety_layouts() {
    // SAFETY:
    // 1. allocation: the buffer belongs to this call.
    //    - initialized: every byte was written before the call.
    //      + aligned: the allocation uses the required alignment.
    //        The allocator guarantee was checked at construction time.
    // 2) lifetime: the buffer remains live for the whole call.
    unsafe {
        complex_safety_contract();
    }

    // SAFETY:
    // * allocation: the buffer belongs to this call.
    //   - initialized: every byte was written before the call.
    // This deliberately omits the nested `aligned` and top-level `lifetime`
    // requirements.
    unsafe {
        complex_safety_contract();
    }
}

pub fn complex_panic_layouts() {
    // PANIC:
    // 1. nonzero: the divisor was checked above.
    //    * bounded: the input is within the supported range.
    //      + audited: this path is included in the arithmetic audit.
    // 2) stable: the backing state cannot change during the call.
    complex_panic_contract();

    // PANIC: the caller checked everything.
    complex_panic_contract();

    // PANIC:
    // + nonzero: the divisor was checked above.
    // + bounded: the input is within the supported range.
    // + audited: this path is included in the arithmetic audit.
    // This deliberately omits `stable`.
    complex_panic_contract();
}

/// # Safety
/// - req_1: content
/// - req_2: content
unsafe fn multi_safety_requirements_with_dash() {
    // PANIC: TODO
    todo!()
}

/// # Safety
///     * req_1: content
///     * req_2: content
unsafe fn multi_safety_requirements_with_asterisks_and_ident() {
    // PANIC: TODO
    todo!()
}

/// # Safety
/// * req_1: content
/// * req_2: content
unsafe fn multi_safety_requirements_with_asterisks() {
    // PANIC: TODO
    todo!()
}

/// # Safety
///
/// 1. allocation: the caller must own the buffer.
///    - initialized: every byte must be initialized.
///      + aligned: the buffer must satisfy the required alignment.
/// 2. lifetime: the buffer must remain live for the duration of the call.
unsafe fn complex_safety_contract() {}

/// # Panics
///
/// 1. nonzero: the divisor must not be zero.
///    * bounded: the input must be within the supported range.
///      + audited: the call path must have been audited.
/// 2) stable: the backing state must not change during the call.
fn complex_panic_contract() {}
