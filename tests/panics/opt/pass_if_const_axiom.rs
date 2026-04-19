extern crate sniff_test_attrs;

#[sniff_test_attrs::check_panics]
fn main() {
    if 1 == 0 {
        panic!();
    }
}
