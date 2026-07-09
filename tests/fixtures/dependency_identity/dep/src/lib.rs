//! Dependency shapes whose cache identity used to depend on how the defining
//! session rendered their paths: trait impls, re-exports, and impls on
//! foreign self types.

pub trait Sniffer {
    fn sniff(&self, flag: bool);
}

pub struct Widget;

impl Sniffer for Widget {
    fn sniff(&self, flag: bool) {
        assert!(flag, "widget expected a set flag");
    }
}

impl Sniffer for Vec<u8> {
    fn sniff(&self, flag: bool) {
        assert!(flag, "buffer expected a set flag");
    }
}

mod internal {
    pub fn run(flag: bool) {
        assert!(flag, "run expected a set flag");
    }
}

pub use internal::run;
