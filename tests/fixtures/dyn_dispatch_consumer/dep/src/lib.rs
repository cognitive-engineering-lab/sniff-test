pub trait Runner {
    fn run(&self);
    fn unused(&self) { panic!("unused vtable method"); }
}

pub fn drive(value: &dyn Runner) {
    value.run();
}

pub fn justified(value: &dyn Runner) {
    // PANIC: the caller accepts failure from this runner.
    // SAFETY: the caller ensures the runner's pointer is valid.
    value.run();
}

/// # Panics
/// The runner can fail.
pub fn propagated(value: &dyn Runner) {
    value.run();
}
