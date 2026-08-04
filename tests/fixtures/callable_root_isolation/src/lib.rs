#![allow(dead_code)]

fn safe_function() {}

fn panicking_function() {
    let pointer = std::hint::black_box(&0_u8 as *const u8);
    unsafe {
        std::hint::black_box(*pointer);
    }
    panic!("unused function-pointer target");
}

pub fn selected_fn_pointer() {
    let callback = std::hint::black_box(safe_function as fn());
    callback();
}

fn unused_fn_pointer_evidence() {
    let callback = std::hint::black_box(panicking_function as fn());
    std::hint::black_box(callback);
}

trait Runner {
    fn run(&self);
}

struct SafeRunner;

impl Runner for SafeRunner {
    fn run(&self) {}
}

struct PanickingRunner;

impl Runner for PanickingRunner {
    fn run(&self) {
        panic!("unused dynamic-dispatch target");
    }
}

pub fn selected_dyn_dispatch() {
    let runner = SafeRunner;
    let runner: &dyn Runner = std::hint::black_box(&runner);
    runner.run();
}

fn unused_dyn_dispatch_evidence() {
    let runner = PanickingRunner;
    let runner: &dyn Runner = std::hint::black_box(&runner);
    std::hint::black_box(runner);
}
