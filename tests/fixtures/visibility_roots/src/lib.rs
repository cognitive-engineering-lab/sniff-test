mod imp {
    pub fn hidden(flag: bool) {
        assert!(flag, "hidden expects a set flag");
    }

    pub fn exported(flag: bool) {
        assert!(flag, "exported expects a set flag");
    }
}

pub use imp::exported;

pub fn public_entry(flag: bool) {
    imp::hidden(flag);
}
