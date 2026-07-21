mod imp {
    pub fn hidden(flag: bool) {
        assert!(flag, "hidden expects a set flag");
    }

    pub fn exported(flag: bool) {
        assert!(flag, "exported expects a set flag");
    }
}

pub use imp::exported;

pub fn public_entry(flag: bool) {
    imp::hidden(flag);
}

pub fn public_unsafe_entry(pointer: *const u8) -> u8 {
    reachable_unsafe(pointer)
}

fn reachable_unsafe(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}

#[allow(dead_code)]
fn unreachable_unsafe(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}

static mut VALUE: u8 = 0;

/// # Safety
///
/// The caller must ensure exclusive access to `VALUE`.
unsafe fn documented_unsafe() -> u8 {
    unsafe { VALUE }
}

pub fn documented_boundary() -> u8 {
    // SAFETY: this fixture runs single-threaded.
    unsafe { documented_unsafe() }
}
