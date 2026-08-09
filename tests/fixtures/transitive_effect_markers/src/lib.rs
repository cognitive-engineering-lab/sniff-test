fn justified_panic_inner() {
    panic!("the outer function documents this invariant");
}

pub fn justified_panic_path() {
    // PANIC: the caller maintains the invariant required by the inner function.
    justified_panic_inner();
}

fn unmarked_panic_inner() {
    panic!("the outer function must report this panic");
}

pub fn unmarked_panic_path() {
    unmarked_panic_inner();
}

fn justified_safety_inner(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}

pub fn justified_safety_path(pointer: *const u8) -> u8 {
    // SAFETY: the caller guarantees that pointer is readable.
    justified_safety_inner(pointer)
}

fn unmarked_safety_inner(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}

pub fn unmarked_safety_path(pointer: *const u8) -> u8 {
    unmarked_safety_inner(pointer)
}
