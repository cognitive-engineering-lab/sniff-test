#![allow(clippy::must_use_candidate)]

/// # Panics
///
/// Panics when the input has no first element.
pub fn first_value(values: &[i32]) -> i32 {
    values[0]
}

/// # Panics
///
/// Panics when `denominator` is zero.
pub fn checked_by_contract(numerator: usize, denominator: usize) -> usize {
    numerator / denominator
}

pub fn caller_inherits_panic_obligations(values: &[i32], denominator: usize) -> i32 {
    let first = first_value(values);
    let quotient = checked_by_contract(values.len(), denominator);
    first + i32::try_from(quotient).unwrap_or(0)
}

fn main() {
    let values = [10, 20, 30];
    let _ = caller_inherits_panic_obligations(&values, 2);
}
