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

pub fn selected_panicking_runner_is_reachable() {
    let runner: &dyn Runner = &Panicker;
    runner.run();
}

pub fn same_trait_vtable_candidates_are_reachable() {
    let panicker = Panicker;
    let _panicking_runner: &dyn Runner = &panicker;

    let safe = SafeRunner;
    let runner: &dyn Runner = &safe;
    runner.run();
}
