extern crate sniff_test_attrs;

fn index(slice: &[i32], i: usize) -> i32 {
    slice[i]
}

#[sniff_test_attrs::check_panics]
fn main() {
    let x = [1];
    index(&x, 1);
}
