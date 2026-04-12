extern crate sniff_test_attrs;

fn foo(ptr: &i32) -> i32 {
    panic!()
}

#[sniff_test_attrs::check_panics]
fn main() {
    let x = 1;
    foo(&x);
}
