const unsafe fn seeded() -> u32 {
    41
}

pub static UNJUSTIFIED_STATIC: u32 = unsafe { seeded() };

pub static JUSTIFIED_STATIC: u32 =
    // SAFETY: seeded has no requirements in this fixture.
    unsafe { seeded() };

pub const UNJUSTIFIED_CONST: u32 = unsafe { seeded() + 1 };
