#![sniff_tool::check_unsafe_pub]

pub trait Hello {
    /// # Safety
    /// can be unsafe
    unsafe fn say_hello(&self);
}

pub struct Bar;
pub struct Foo;

impl Hello for Bar {
    /// # Safety
    /// can be unsafe
    unsafe fn say_hello(&self) {
        let x = 10;
        let ptr = &raw const x;
        println!("val is {}", unsafe { *ptr });
    }
}

pub fn helloer<T: Hello>(t: T) {
    /// SAFETY: I checked this one is safe
    unsafe {
        t.say_hello();
    }
}

fn main() {}

// Notes from justus
// - instance safety for some traits
// - when it cant be done alwyas deny and just allow specific instances
