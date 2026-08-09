pub fn const_false_call() {
    if 1 == 0 {
        documented_panic();
    }
}

pub fn documented_inlinable_call() -> usize {
    greater_than_zero(10)
}

/// # Panics
/// Panics when called.
fn documented_panic() {
    panic!("documented panic")
}

/// # Panics
/// Panics when `count` is zero.
fn greater_than_zero(count: usize) -> usize {
    if count > 0 {
        count
    } else {
        panic!("count should be greater than zero")
    }
}
