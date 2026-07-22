/// # Panics
///
/// Panics unconditionally.
pub fn documented() {
    panic!("documented");
}

pub fn mixed() {
    documented();
    panic!("undocumented");
}
