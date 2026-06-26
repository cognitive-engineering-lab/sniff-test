pub trait Runner {
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

pub fn entry() {
    let panicker = Panicker;
    let _panicking_runner: &dyn Runner = &panicker;

    let safe = SafeRunner;
    let runner: &dyn Runner = &safe;
    runner.run();
}
