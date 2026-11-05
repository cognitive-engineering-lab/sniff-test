pub trait Runner {
    /// # Panics
    ///
    /// Implementations may panic while running.
    fn run(&self);
}

pub struct Panicker;

impl Runner for Panicker {
    fn run(&self) {
        panic!("dynamic dispatch panic");
    }
}

pub struct SafeRunner;

impl Runner for SafeRunner {
    fn run(&self) {}
}

pub fn locally_constructed_implementation_uses_trait_contract() {
    let runner: &dyn Runner = &Panicker;
    runner.run();
}

pub fn observed_casts_select_all_compatible_implementations() {
    let panicker = Panicker;
    let _panicking_runner: &dyn Runner = &panicker;

    let safe = SafeRunner;
    let runner: &dyn Runner = &safe;
    runner.run();
}
