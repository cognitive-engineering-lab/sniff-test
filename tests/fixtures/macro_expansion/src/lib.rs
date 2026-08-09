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

macro_rules! justified_const_assert {
    ($condition:expr) => {
        // PANIC: macro caller guarantees the macro precondition.
        assert!($condition);
    };
}

pub fn macro_internal_marker(flag: bool) {
    justified_const_assert!(flag);
}
