/// # Panics
/// The argument must be nonzero.
const fn documented(value: usize) -> usize {
    assert!(value != 0);
    value
}

const fn transitive(value: usize) -> usize {
    documented(value)
}

pub fn compile_time() -> usize {
    let _: [u8; transitive(1)] = [0];
    const { const { transitive(1) } }
}

pub fn runtime(value: usize) -> usize {
    transitive(value)
}

pub fn mixed(value: usize) -> usize {
    let checked = const { transitive(1) };
    checked + transitive(value)
}
