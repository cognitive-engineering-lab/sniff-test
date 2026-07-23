pub fn root(pointer: *const u8) -> u8 {
    middle(pointer)
}

fn middle(pointer: *const u8) -> u8 {
    deeper(pointer)
}

fn deeper(pointer: *const u8) -> u8 {
    unsafe_leaf(pointer)
}

fn unsafe_leaf(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}
