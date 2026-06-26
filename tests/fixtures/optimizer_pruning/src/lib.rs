pub fn const_false_axiom() {
    if 1 == 0 {
        panic!("unreachable const comparison");
    }
}

pub fn const_false_call() {
    if 1 == 0 {
        documented_panic();
    }
}

pub fn literal_false_axiom() {
    if false {
        panic!("unreachable false branch");
    }
}

pub fn literal_false_call() {
    if false {
        documented_panic();
    }
}

pub fn documented_inlinable_call() -> usize {
    greater_than_zero(10)
}

pub fn documented_inline_always_call() -> usize {
    greater_than_zero_inline(10)
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

/// # Panics
/// Panics when `count` is zero.
#[inline(always)]
fn greater_than_zero_inline(count: usize) -> usize {
    if count > 0 {
        count
    } else {
        panic!("count should be greater than zero")
    }
}
