#![sniff_tool::check_unsafe]

fn foo(ptr: *const i32) -> i32 {
    unsafe { *ptr }
}

fn bar(ptr: *const i32) -> i32 {
    unsafe { *ptr }
}

fn main() {
    let x = 0;
    foo(&raw const x);
    bar(&raw const x);
}
