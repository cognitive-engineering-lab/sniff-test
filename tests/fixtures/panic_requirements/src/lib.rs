/// # Panics
///
/// Panics when any listed requirement is violated.
///
/// Requirements:
///
/// - nonzero: denominator must not be zero.
/// - bounded[total]: total must be bounded by the caller.
/// - audited:
pub fn documented_ratio(total: usize, denominator: usize) -> usize {
    total / denominator
}

pub fn satisfied(total: usize, denominator: usize) -> usize {
    // PANIC:
    // The caller validates the panic contract before this call.
    // Requirements:
    // - nonzero: caller checked the denominator.
    // - bounded[total]: caller checked the total bound.
    // - audited: this call site is covered by the API audit.
    documented_ratio(total, denominator)
}

pub fn partially_satisfied(total: usize, denominator: usize) -> usize {
    // PANIC:
    // - nonzero: caller checked the denominator.
    documented_ratio(total, denominator)
}
