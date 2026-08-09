pub fn read_dependency(pointer: *const u8) -> u8 {
    dependency_safety::read_byte(pointer)
}
