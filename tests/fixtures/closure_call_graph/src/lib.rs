pub fn basic_closure_panics() {
    let panic = || panic!("called closure");
    calls_fn(panic);
}

pub fn dyn_box_closure_boundary() {
    let panics: Box<dyn Fn() -> i32> = Box::new(|| panic!("boxed dyn closure"));
    calls_dyn_box(panics);
}

fn calls_fn(function: impl Fn() -> i32) -> i32 {
    function()
}

fn calls_dyn_box(function: Box<dyn Fn() -> i32>) -> i32 {
    function()
}
