/// # Safety
///
/// Requirements:
///
/// - valid_ptr: pointer must be non-null.
/// - initialized: pointer must reference initialized memory.
unsafe fn read_byte(ptr: *const u8) -> u8 {
    // SAFETY:
    // - valid_ptr: delegated to the caller.
    // - initialized: delegated to the caller.
    unsafe { *ptr }
}

pub fn panic_comment_before_expr_ok(total: usize, denominator: usize) -> usize {
    // PANIC: caller checked denominator is nonzero.
    total / denominator
}

pub fn panic_comment_before_let_ok(total: usize, denominator: usize) -> usize {
    // PANIC: caller checked denominator is nonzero.
    let value = total / denominator;
    value
}

// PANIC: this comment is on the function definition, not the division expression.
pub fn panic_comment_on_function_def_bad(total: usize, denominator: usize) -> usize {
    total / denominator
}

pub fn safety_comment_before_block_ok() -> u8 {
    let byte = 7;
    let ptr = &raw const byte;

    // SAFETY:
    // - valid_ptr: pointer was created from a live reference.
    // - initialized: `byte` was initialized above.
    unsafe {
        read_byte(ptr)
    }
}

pub fn safety_comment_before_let_ok() -> u8 {
    let byte = 7;
    let ptr = &raw const byte;

    // SAFETY:
    // - valid_ptr: pointer was created from a live reference.
    // - initialized: `byte` was initialized above.
    let value = unsafe { read_byte(ptr) };
    value
}

// SAFETY: this comment is on the function definition, not the unsafe block.
pub fn safety_comment_on_function_def_bad() -> u8 {
    let byte = 7;
    let ptr = &raw const byte;

    unsafe { read_byte(ptr) }
}
