pub trait Runner {
    fn run(&self);
}

pub struct Panicker;

impl Runner for Panicker {
    fn run(&self) {
        panic!("dynamic dispatch panic");
    }
}

pub fn entry() {
    let runner: &dyn Runner = &Panicker;
    runner.run();
}
