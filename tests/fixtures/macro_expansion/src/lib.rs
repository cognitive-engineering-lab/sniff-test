macro_rules! const_assert {
    ($condition:expr) => {
        assert!($condition);
    };
}

macro_rules! static_assert {
    ($condition:expr) => {
        const_assert!($condition);
    };
}

pub fn macro_wrapped(flag: bool) {
    static_assert!(flag);
}

pub fn justified_macro(flag: bool) {
    // PANIC: caller guarantees the macro precondition.
    static_assert!(flag);
}

pub fn direct_macro(flag: bool) {
    const_assert!(flag);
}

pub fn direct_assert(flag: bool) {
    assert!(flag);
}

macro_rules! justified_const_assert {
    ($condition:expr) => {
        // PANIC: macro caller guarantees the macro precondition.
        assert!($condition);
    };
}

pub fn macro_internal_marker(flag: bool) {
    justified_const_assert!(flag);
}
