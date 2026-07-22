fn second() {
    third();
}

fn third() {}

pub fn leaf(pointer: *const u8) {
    let _ = unsafe { *pointer };
    second();
}
