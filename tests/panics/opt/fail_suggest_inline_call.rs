extern crate sniff_test_attrs;

/// # Panics
/// This function will panic if `count` is zero.
#[inline(always)]
fn greater_than_zero(count: usize) -> usize {
    if count > 0 {
        count
    } else {
        panic!("count should be greater than zero!");
    }
}

#[sniff_test_attrs::check_panics]
fn main() {
    println!("count is {}", greater_than_zero(10));
}
