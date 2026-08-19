fn converging_panic_effect() {
    panic!("boom");
}

fn uncovered_panic_branch() {
    converging_panic_effect();
}

pub fn converging_panic_paths_preserve_uncovered_route() {
    // PANIC: only this direct path is justified.
    converging_panic_effect();
    uncovered_panic_branch();
}

fn converging_safety_effect(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}

fn uncovered_safety_branch(pointer: *const u8) -> u8 {
    converging_safety_effect(pointer)
}

pub fn converging_safety_paths_preserve_uncovered_route(pointer: *const u8) -> u8 {
    // SAFETY: only this direct path is justified.
    let direct = converging_safety_effect(pointer);
    direct + uncovered_safety_branch(pointer)
}

fn covered_panic_inner() {
    panic!("the outer function documents this invariant");
}

pub fn transitive_panic_marker_covers_inner_effect() {
    // PANIC: the caller maintains the invariant required by the inner function.
    covered_panic_inner();
}

fn uncovered_panic_inner() {
    panic!("the outer function must report this panic");
}

pub fn transitive_panic_path_exposes_uncovered_effect() {
    uncovered_panic_inner();
}

fn covered_safety_inner(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}

pub fn transitive_safety_marker_covers_inner_effect(pointer: *const u8) -> u8 {
    // SAFETY: the caller guarantees that pointer is readable.
    covered_safety_inner(pointer)
}

fn uncovered_safety_inner(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}

pub fn transitive_safety_path_exposes_uncovered_effect(pointer: *const u8) -> u8 {
    uncovered_safety_inner(pointer)
}
