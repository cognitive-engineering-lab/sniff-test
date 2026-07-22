pub fn read_byte(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}
