//! A dependency trait implemented for a foreign self type. Its canonical impl
//! path must identify the same function in the defining and consuming
//! compilation sessions.

pub trait Sniffer {
    fn sniff(&self, flag: bool);
}

impl Sniffer for Vec<u8> {
    fn sniff(&self, flag: bool) {
        assert!(flag, "buffer expected a set flag");
    }
}
