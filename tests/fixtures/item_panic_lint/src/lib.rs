#![cfg_attr(sniff_test, feature(register_tool), register_tool(sniff_test))]

fn panic_source() {
    panic!("source");
}

#[cfg_attr(sniff_test, deny(sniff_test::panic))]
fn denied() {
    panic_source();
}

#[cfg_attr(sniff_test, warn(sniff_test::panic))]
fn warned() {
    panic_source();
}

#[cfg_attr(sniff_test, allow(sniff_test::panic))]
fn allowed() {
    panic_source();
}

#[cfg_attr(sniff_test, deny(sniff_test::panic))]
fn justified() {
    // PANIC: This path is intentionally handled here.
    panic!("handled");
}

/// # Panics
///
/// This function intentionally propagates its panic contract.
#[cfg_attr(sniff_test, deny(sniff_test::panic))]
fn documented() {
    panic!("documented");
}

struct Holder;

impl Holder {
    #[cfg_attr(sniff_test, deny(sniff_test::panic))]
    fn method(&self) {
        panic_source();
    }
}

#[cfg_attr(sniff_test, deny(sniff_test::safety))]
fn unsafe_unhandled(ptr: *const u8) -> u8 {
    unsafe { *ptr }
}

#[cfg_attr(sniff_test, deny(sniff_test::safety))]
fn unsafe_justified(ptr: *const u8) -> u8 {
    // SAFETY: the caller guarantees that ptr points to a valid byte.
    unsafe { *ptr }
}

#[cfg_attr(sniff_test, deny(sniff_test::allocation))]
fn allocation_unhandled() -> Box<u32> {
    Box::new(7)
}

#[cfg_attr(sniff_test, deny(sniff_test::allocation))]
fn allocation_justified() -> Box<u32> {
    // ALLOCATION: this function intentionally allocates one box.
    Box::new(8)
}

#[cfg_attr(sniff_test, deny(sniff_test::file))]
fn file_unhandled(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::write(path, b"data")
}

#[cfg_attr(sniff_test, deny(sniff_test::file))]
fn file_justified(path: &std::path::Path) -> std::io::Result<()> {
    // FILE: this function intentionally writes the supplied path.
    std::fs::write(path, b"data")
}
