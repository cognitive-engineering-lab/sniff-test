//! One unmarked unsafe operation per detected kind.

use std::arch::asm;

static mut COUNTER: u32 = 0;

unsafe extern "C" {
    static ENV_FLAG: u32;
}

pub union Bits {
    pub word: u32,
    pub bytes: [u8; 4],
}

pub fn deref_unjustified(ptr: *const u32) -> u32 {
    unsafe { *ptr }
}

pub fn mutable_static_unjustified() -> u32 {
    unsafe { COUNTER }
}

pub fn extern_static_unjustified() -> u32 {
    unsafe { ENV_FLAG }
}

pub fn union_read_unjustified(bits: &Bits) -> u32 {
    unsafe { bits.word }
}

pub fn asm_unjustified() {
    unsafe {
        asm!("nop");
    }
}
