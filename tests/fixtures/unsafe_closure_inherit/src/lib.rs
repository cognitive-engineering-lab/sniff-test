unsafe fn dangerous() {}

pub fn justified_closure() {
    // SAFETY: dangerous has no requirements in this fixture.
    unsafe {
        (|| dangerous())();
    }
}

pub fn unjustified_closure() {
    unsafe {
        (|| dangerous())();
    }
}

pub fn justified_direct() {
    // SAFETY: dangerous has no requirements in this fixture.
    unsafe {
        dangerous();
    }
}
