pub fn dependency_effect() {
    dep_c::panic_effect();
}

pub fn consume(callback: impl Fn()) {
    callback();
}

pub fn safety_effect() {
    dep_c::safety_effect();
}
