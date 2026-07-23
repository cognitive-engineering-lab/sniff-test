fn second() {
    third();
}

fn third() {}

pub fn incomplete() {
    second();
}
