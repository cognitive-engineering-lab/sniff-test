pub fn panic_effect() {
    panic!("transitive dependency panic");
}

pub fn safety_effect() {
    let pointer = std::ptr::null::<u8>();
    unsafe { let _value = *pointer; }
}
