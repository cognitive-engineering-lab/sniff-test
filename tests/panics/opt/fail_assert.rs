extern crate sniff_test_attrs;

#[sniff_test_attrs::check_panics]
fn main() {
    assert!(1 == 0);
}
