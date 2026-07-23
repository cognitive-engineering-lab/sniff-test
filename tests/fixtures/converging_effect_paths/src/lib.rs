fn panic_effect() {
    panic!("boom");
}

fn raw_panic_branch() {
    panic_effect();
}

pub fn converging_panic_paths() {
    // PANIC: only this direct path is justified.
    panic_effect();
    raw_panic_branch();
}

fn safety_effect(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}

fn raw_safety_branch(pointer: *const u8) -> u8 {
    safety_effect(pointer)
}

pub fn converging_safety_paths(pointer: *const u8) -> u8 {
    // SAFETY: only this direct path is justified.
    let direct = safety_effect(pointer);
    direct + raw_safety_branch(pointer)
}
