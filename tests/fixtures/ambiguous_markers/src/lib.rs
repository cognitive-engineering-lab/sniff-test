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

/// # Panics
///
/// This configured sink always terminates abnormally in production.
pub fn configured_sink() {}

macro_rules! call_documented_and_sink {
    () => {{
        let _ = ratio(1, 1);
        configured_sink();
    }};
}

macro_rules! call_documented_and_sink_with_one_marker {
    () => {{
        // PANIC: this fixture guards both operations.
        call_documented_and_sink!()
    }};
}

pub fn marker_covers_documented_call_and_sink() {
    call_documented_and_sink_with_one_marker!();
}

/// # Panics
///
/// This fixture contract represents the first independent effect source.
pub fn first_documented_source() {}

/// # Panics
///
/// This fixture contract represents the second independent effect source.
pub fn second_documented_source() {}

fn shared_documented_sources() {
    first_documented_source();
    second_documented_source();
}

pub fn marked_path_to_shared_sources() {
    // PANIC: this path accepts both documented effects.
    shared_documented_sources();
}

pub fn unmarked_path_to_shared_sources() {
    shared_documented_sources();
}
