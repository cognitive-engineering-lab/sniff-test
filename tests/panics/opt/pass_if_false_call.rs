extern crate sniff_test_attrs;

/// # Panics
/// This function can panic!
fn can_panic() {
    panic!();
}

#[sniff_test_attrs::check_panics]
fn main() {
    if false {
        can_panic();
    }
}
