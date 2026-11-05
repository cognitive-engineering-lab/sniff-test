pub fn local_selected(denominator: usize) -> usize {
    12 / denominator
}

pub fn local_control(denominator: usize) -> usize {
    12 / denominator
}

pub fn named_selected() {
    justification_dependency::contract();
}

pub fn named_control() {
    justification_dependency::contract();
}

pub fn dependency_selected() {
    justification_dependency::selected();
}

pub fn dependency_control() {
    justification_dependency::control();
}

#[allow(dead_code)]
fn ambiguous(first: usize, second: usize) {
    let _ = 12 / first;
    let _ = 24 / second;
}
