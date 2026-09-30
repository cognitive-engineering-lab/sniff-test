#![allow(dead_code)]

#[cfg(not(feature = "public-main"))]
fn main() {
    private_helper();
}

#[cfg(feature = "public-main")]
pub fn main() {
    private_helper();
}

fn private_helper() {
    panic!("reachable private helper");
}

fn unused_private() {
    panic!("unused private function");
}

pub fn unused_public() {
    panic!("unused public function");
}
