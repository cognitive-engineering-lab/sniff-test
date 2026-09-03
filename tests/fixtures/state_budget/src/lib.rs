//! A small state budget stops effect propagation before it reaches the public
//! root. The report should retain the concrete frontier and path.

fn step_one(flag: bool) {
    step_two(flag);
}

fn step_two(flag: bool) {
    assert!(flag, "flag must be set");
}

pub fn deep_chain(flag: bool) {
    step_one(flag);
}
