/// # Safety
///
/// Requirements:
/// - valid_ptr: pointer must be non-null.
pub fn documented_contract(_ptr: *const u8) {}

pub fn satisfies_requirement() {
    let byte = 7;
    let ptr = &raw const byte;

    // SAFETY:
    // - valid_ptr: pointer was created from a live reference.
    documented_contract(ptr);
}

pub fn misses_requirement() {
    let byte = 7;
    documented_contract(&raw const byte);
}
