#![allow(dead_code)]

pub fn public_panic() {
    panic!("public root");
}

fn private_panic() {
    panic!("private root");
}
