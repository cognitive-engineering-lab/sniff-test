pub trait Action {
    fn apply(flag: bool);
}

#[inline(never)]
pub fn invoke<T: Action>(flag: bool) {
    // SAFETY: these private helpers have no caller-visible preconditions.
    unsafe {
        first::<T>();
        second::<T>();
    }
    T::apply(flag);
}

#[inline(never)]
unsafe fn first<T>() {
    std::hint::black_box(std::mem::size_of::<T>());
}

#[inline(never)]
unsafe fn second<T>() {
    std::hint::black_box(std::mem::align_of::<T>());
}
