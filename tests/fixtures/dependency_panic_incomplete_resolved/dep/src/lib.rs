fn second() {
    third();
}

fn third() {}

pub fn incomplete_with_known_panic(flag: bool) {
    assert!(flag, "known panic before truncation");
    second();
}
