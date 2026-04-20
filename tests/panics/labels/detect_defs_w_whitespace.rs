extern crate sniff_test_attrs;

/// # Panics    
/// This function can panic!
fn spaces_after() {
    panic!();
}

/// # Panics        
/// This function can panic!
fn tabs_after() {
    panic!();
}

/// # Panics            
/// This function can panic!
fn mix_after() {
    panic!();
}

#[sniff_test_attrs::check_panics]
fn main() {
    spaces_after();
    tabs_after();
    mix_after();
}
