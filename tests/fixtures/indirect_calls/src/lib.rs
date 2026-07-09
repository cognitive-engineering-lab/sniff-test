pub trait Risky {
    /// # Panics
    ///
    /// Panics when `flag` is false.
    fn documented(&self, flag: bool);

    fn undocumented(&self, flag: bool);
}

pub fn call_documented<T: Risky>(value: &T, flag: bool) {
    value.documented(flag);
}

pub fn call_undocumented<T: Risky>(value: &T, flag: bool) {
    value.undocumented(flag);
}

pub fn call_pointer(callee: fn(bool), flag: bool) {
    callee(flag);
}
