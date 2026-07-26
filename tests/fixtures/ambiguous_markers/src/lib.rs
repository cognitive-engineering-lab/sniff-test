/// # Panics
///
/// Panics when `denominator` is zero.
pub fn ratio(total: usize, denominator: usize) -> usize {
    total / denominator
}

pub fn shared_block_marker(a: usize, b: usize, denominator: usize) -> usize {
    // PANIC: all denominators in this guarded block are nonzero.
    {
        let first = ratio(a, denominator);
        let second = ratio(b, denominator);
        first.saturating_add(second)
    }
}

/// # Panics
///
/// Requirements:
///
/// - nonzero: denominator must not be zero.
/// - nonzero: total must be bounded by the caller.
pub fn duplicate_name_ratio(total: usize, denominator: usize) -> usize {
    total / denominator
}

pub fn duplicate_name_marker(total: usize, denominator: usize) -> usize {
    // PANIC:
    // - nonzero: caller checked the local preconditions.
    duplicate_name_ratio(total, denominator)
}

fn shared_ratio(total: usize, denominator: usize) -> usize {
    ratio(total, denominator)
}

fn unmarked_route(total: usize, denominator: usize) -> usize {
    shared_ratio(total, denominator)
}

fn marked_route(total: usize, denominator: usize) -> usize {
    shared_ratio(total, denominator).saturating_add(ratio(total, denominator))
}

pub fn marker_on_noncanonical_route(total: usize, denominator: usize) -> usize {
    let first = unmarked_route(total, denominator);
    // PANIC: the denominator is nonzero on this route.
    let second = marked_route(total, denominator);
    first.saturating_add(second)
}
