#![allow(dead_code)]

pub fn public_panic() {
    panic!("public root");
}

pub fn public_safe() -> usize {
    private_safe()
}

fn private_panic() {
    panic!("private root");
}

fn private_safe() -> usize {
    1
}
