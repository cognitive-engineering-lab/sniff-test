pub fn basic_closure_panics() {
    let panic = || panic!("called closure");
    calls_fn(panic);
}

pub fn unused_closure_argument() {
    let panic = || panic!("unused closure");
    does_not_call_fn(panic);
}

pub fn fn_pointer_closure_boundary() {
    let panic = || panic!("function pointer closure");
    let dont_panic = || 0;
    let maybe_panic: fn() -> i32 = if true { panic } else { dont_panic };
    calls_fn(maybe_panic);
}

pub fn dyn_box_closure_boundary() {
    let panics: Box<dyn Fn() -> i32> = Box::new(|| panic!("boxed dyn closure"));
    calls_dyn_box(panics);
}

pub fn captured_closure_panics() {
    let panic_closure = || panic!("captured closure");
    let might_panic = || panic_closure();
    calls_fn(might_panic);
}

pub fn boxed_captured_closure_panics() {
    let panic_closure = || panic!("boxed captured closure");
    let might_panic = || panic_closure();
    calls_deref_fn(Box::new(might_panic));
}

pub fn unused_closure_definition() {
    let _closure = || panic!("unused closure definition");
}

fn calls_fn(function: impl Fn() -> i32) -> i32 {
    function()
}

fn does_not_call_fn(_function: impl Fn() -> i32) -> i32 {
    0
}

fn calls_dyn_box(function: Box<dyn Fn() -> i32>) -> i32 {
    function()
}

fn calls_deref_fn(function: impl std::ops::Deref<Target = impl Fn() -> i32>) -> i32 {
    function()
}
