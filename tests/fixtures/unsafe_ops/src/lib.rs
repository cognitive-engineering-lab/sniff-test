//! One unsafe operation per detected kind, each with a justified and an
//! unjustified instance.

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

pub fn deref_justified(ptr: *const u32) -> u32 {
    // SAFETY: callers pass a pointer derived from a live reference.
    unsafe { *ptr }
}

pub fn mutable_static_unjustified() -> u32 {
    unsafe { COUNTER }
}

pub fn mutable_static_justified() -> u32 {
    // SAFETY: single-threaded fixture; no concurrent access exists.
    unsafe { COUNTER }
}

pub fn extern_static_unjustified() -> u32 {
    unsafe { ENV_FLAG }
}

pub fn union_read_unjustified(bits: &Bits) -> u32 {
    unsafe { bits.word }
}

pub fn union_write_is_safe(bits: &mut Bits) {
    bits.word = 7;
}

pub fn asm_unjustified() {
    unsafe {
        asm!("nop");
    }
}

pub fn asm_justified() {
    // SAFETY: `nop` has no observable effects.
    unsafe {
        asm!("nop");
    }
}
