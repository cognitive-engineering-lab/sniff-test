#[cfg(feature = "dangerous")]
pub fn feature_root(flag: bool) {
    assert!(flag);
}

#[cfg(not(feature = "dangerous"))]
pub fn safe_root() {}
