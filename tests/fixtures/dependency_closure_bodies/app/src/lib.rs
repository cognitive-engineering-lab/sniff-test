pub fn root(value: Option<u8>) -> Option<u8> {
    dependency_closure_dep::check_value(value)
}

pub fn justified() -> Option<u8> {
    dependency_closure_dep::justified(Some(1))
}

pub fn unsafe_body(pointer: *const u8) -> u8 {
    dependency_closure_dep::read_pointer(pointer)
}

pub fn nested(value: Option<u8>) -> Option<u8> {
    dependency_closure_dep::nested(value)
}

pub fn returned(value: Option<u8>) -> Option<u8> {
    let mut closure = dependency_closure_dep::make_consumer(value);
    closure()
}

struct Quiet;
struct Panicking;

impl dependency_closure_dep::Action for Quiet {
    fn run(&self) {}
}

impl dependency_closure_dep::Action for Panicking {
    fn run(&self) {
        panic!("concrete closure dispatch");
    }
}

pub fn quiet_dispatch() {
    dependency_closure_dep::dispatch(Quiet)();
}

pub fn panicking_dispatch() {
    dependency_closure_dep::dispatch(Panicking)();
}

pub fn inherited_safety(value: &u8) -> u8 {
    dependency_closure_dep::nested_read(value)
}

pub fn unused_closure(value: Option<u8>) {
    let _closure = dependency_closure_dep::make_consumer(value);
}
