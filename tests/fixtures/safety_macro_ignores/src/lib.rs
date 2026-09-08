use std::fmt::Write;

pub fn format_and_dereference(value: i32) {
    let mut output = String::new();
    let _ = write!(&mut output, "{value}");
    let _ = format!("{value}");

    let pointer = &value as *const i32;
    unsafe {
        let _ = *pointer;
    }
}
