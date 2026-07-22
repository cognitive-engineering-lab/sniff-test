pub fn application(pointer: *const u8) {
    // SAFETY: the caller guarantees that the pointer is readable.
    dependency_safety_incomplete_middle::middle(pointer);
}
