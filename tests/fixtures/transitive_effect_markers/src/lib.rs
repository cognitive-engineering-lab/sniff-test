fn panic_inner() {
    panic!("the outer function documents this invariant");
}

pub fn justified_panic_path() {
    // PANIC: the caller maintains the invariant required by panic_inner.
    panic_inner();
}

fn safety_inner(pointer: *const u8) -> u8 {
    let first = unsafe { *pointer };
    let second = unsafe { *pointer };
    first + second
}

pub fn justified_safety_path(pointer: *const u8) -> u8 {
    // SAFETY: the caller guarantees that pointer is readable.
    safety_inner(pointer)
}
