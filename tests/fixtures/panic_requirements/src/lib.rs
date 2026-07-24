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

pub fn unnamed_marker(total: usize, denominator: usize) -> usize {
    // PANIC: caller checked the denominator.
    documented_ratio(total, denominator)
}

pub fn bullet_without_marker(total: usize, denominator: usize) -> usize {
    // - nonzero: caller checked the denominator.
    documented_ratio(total, denominator)
}

pub fn empty_marker(total: usize, denominator: usize) -> usize {
    // PANIC:
    documented_ratio(total, denominator)
}

pub fn empty_requirement(total: usize, denominator: usize) -> usize {
    // PANIC:
    // - nonzero:
    // - bounded[total]: caller checked the total bound.
    // - audited: this call site is covered by the API audit.
    documented_ratio(total, denominator)
}

pub fn safety_marker_does_not_satisfy_panic(total: usize, denominator: usize) -> usize {
    // PANIC:
    // SAFETY: this justifies unsafe code, not panic behavior.
    // - nonzero: this must not satisfy the panic contract.
    // - bounded[total]: this must not satisfy the panic contract.
    // - audited: this must not satisfy the panic contract.
    documented_ratio(total, denominator)
}

pub fn safety_marker_stops_partial_panic_block(total: usize, denominator: usize) -> usize {
    // PANIC:
    // - nonzero: caller checked the denominator.
    // SAFETY: this starts a different marker block.
    // - bounded[total]: this must not satisfy the panic contract.
    // - audited: this must not satisfy the panic contract.
    documented_ratio(total, denominator)
}

fn forwarded_ratio(total: usize, denominator: usize) -> usize {
    documented_ratio(total, denominator)
}

pub fn transitive_partial_marker(total: usize, denominator: usize) -> usize {
    // PANIC:
    // - nonzero: caller checked the denominator.
    forwarded_ratio(total, denominator)
}

pub fn transitive_unrelated_marker(total: usize, denominator: usize) -> usize {
    // PANIC:
    // - initialized: this does not satisfy the downstream panic contract.
    forwarded_ratio(total, denominator)
}

pub fn transitive_satisfied(total: usize, denominator: usize) -> usize {
    // PANIC:
    // - nonzero: caller checked the denominator.
    // - bounded[total]: caller checked the total bound.
    // - audited: this call site is covered by the API audit.
    forwarded_ratio(total, denominator)
}
