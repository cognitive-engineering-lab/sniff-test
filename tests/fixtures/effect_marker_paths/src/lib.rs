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

unsafe fn multiline_unsafe_value() -> Option<u8> {
    Some(42)
}

#[rustfmt::skip]
pub fn multiline_let_else_marker_applies_to_containing_statement() -> u8 {
    // SAFETY: this fixture's unsafe function has no preconditions.
    let Some(value) =
        (unsafe { multiline_unsafe_value() })
    else {
        return 0;
    };
    value
}

#[rustfmt::skip]
pub fn marker_does_not_cross_an_intervening_statement() -> u8 {
    // SAFETY: this marker applies only to the unrelated statement.
    let _unrelated = 0;
    let Some(value) =
        (unsafe { multiline_unsafe_value() })
    else {
        return 0;
    };
    value
}

pub fn let_else_marker_does_not_cover_the_else_body(value: Option<u8>) -> u8 {
    // SAFETY: this marker belongs to the let-else statement, not its else body.
    let Some(value) = value else {
        return unsafe { multiline_unsafe_value() }.unwrap_or(0);
    };
    value
}

pub fn marker_on_an_ordinary_enclosing_block_does_not_cover_its_tail() -> Option<u8> {
    // SAFETY: this marker belongs to the enclosing block expression only.
    {
        let _unrelated = 0;
        unsafe { multiline_unsafe_value() }
    }
}
