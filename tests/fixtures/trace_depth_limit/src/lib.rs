//! A call chain deeper than the configured trace depth; the panic at its end
//! is invisible to the truncated traversal.

pub fn shallow() {}

fn step_one(flag: bool) {
    step_two(flag);
}

fn step_two(flag: bool) {
    step_three(flag);
}

fn step_three(flag: bool) {
    step_four(flag);
}

fn step_four(flag: bool) {
    step_five(flag);
}

fn step_five(flag: bool) {
    assert!(flag, "flag must be set");
}

pub fn deep_chain(flag: bool) {
    step_one(flag);
}
