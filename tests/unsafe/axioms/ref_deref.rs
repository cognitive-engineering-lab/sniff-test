extern crate sniff_test_attrs;

fn foo(ptr: &i32) -> i32 {
    *ptr
}

#[sniff_test_attrs::check_unsafe]
fn main() {
    let x = 1;
    foo(&x);
}
