/// # Safety
///
/// Requirements:
///
/// - ready: the first target's precondition must hold.
unsafe fn first_target() {}

/// # Safety
///
/// Requirements:
///
/// - ready: the second target's precondition must hold.
unsafe fn second_target() {}

pub fn independently_marked_calls() {
    let first: unsafe fn() = first_target;
    let second: unsafe fn() = second_target;

    // SAFETY: the erased pointer targets are known in this test.
    // - ready: both observed target preconditions hold here.
    unsafe { first() }

    // SAFETY: the erased pointer targets are known, but `ready` is not established.
    unsafe { second() }
}
