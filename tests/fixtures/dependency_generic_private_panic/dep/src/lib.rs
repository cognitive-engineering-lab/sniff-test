pub fn api<T>(flag: bool) {
    let _ = std::marker::PhantomData::<T>;
    hidden(flag);
}

#[inline(never)]
fn hidden(flag: bool) {
    assert!(flag, "private dependency helper expected a set flag");
}
