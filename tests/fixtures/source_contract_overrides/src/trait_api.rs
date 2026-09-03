pub trait Operation {
    fn execute(&self);
}

pub fn caller<T: Operation>(value: &T) {
    value.execute();
}
