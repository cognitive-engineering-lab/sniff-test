pub fn named_safety_contract_accepts_one_line() {
    // SAFETY: the caller established the contract.
    unsafe {
        named_safety_contract();
    }
}

pub fn unnamed_safety_contract_accepts_one_line() {
    // SAFETY: the caller established the contract.
    unsafe {
        unnamed_safety_contract();
    }
}

pub fn named_panic_contract_accepts_one_line() {
    // PANIC: the caller established the contract.
    named_panic_contract();
}

pub fn unnamed_panic_contract_accepts_one_line() {
    // PANIC: the caller established the contract.
    unnamed_panic_contract();
}

/// # Safety
///
/// - allocation: the caller must own the allocation.
///   - initialized: every byte must be initialized.
///   - aligned: the allocation must have the required alignment.
/// - lifetime: the allocation must remain live for the call.
unsafe fn named_safety_contract() {}

/// # Safety
///
/// - The caller must own the allocation.
///   - Every byte must be initialized.
///   - The allocation must have the required alignment.
/// - The allocation must remain live for the call.
unsafe fn unnamed_safety_contract() {}

/// # Panics
///
/// 1. nonzero: the divisor must not be zero.
///    1. bounded: the input must be within the supported range.
///    2. audited: the call path must have been audited.
/// 2. stable: the backing state must not change during the call.
fn named_panic_contract() {}

/// # Panics
///
/// 1. The divisor must not be zero.
///    1. The input must be within the supported range.
///    2. The call path must have been audited.
/// 2. The backing state must not change during the call.
fn unnamed_panic_contract() {}
