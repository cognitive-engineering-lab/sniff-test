pub trait Operation {
    fn execute(&self);
}

pub fn caller<T: Operation>(value: &T) {
    value.execute();
}

pub fn justified<T: Operation>(value: &T) {
    // PANIC:
    // - implemented: this caller accepts the implementation's contract.
    value.execute();
}
