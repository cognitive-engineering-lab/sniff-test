pub trait Action {
    fn apply(flag: bool);
}

#[inline(never)]
pub fn invoke<T: Action>(flag: bool) {
    T::apply(flag);
}
