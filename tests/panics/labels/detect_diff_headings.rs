extern crate sniff_test_attrs;

/// # Panics
/// This function will panic!
fn func1() {
    panic!()
}

/// ## Panics
/// This function will panic!
fn func2() {
    panic!()
}

/// ### Panics
/// This function will panic!
fn func3() {
    panic!()
}

/// #### Panics
/// This function will panic!
fn func4() {
    panic!()
}

#[sniff_test_attrs::check_panics]
fn main() {
    func1();
    func2();
    func3();
    func4();
}
