pub trait Risky {
    #[doc = include_str!("../doc/panic.md")]
    fn checked(&self, valid: bool);
}

pub struct Worker;

impl Risky for Worker {
    fn checked(&self, valid: bool) {
        assert!(valid);
    }
}

pub fn run(valid: bool) {
    Worker.checked(valid);
}
