pub trait TraitDefaultMethod {
    fn default_panic(&self) {
        panic!("trait default method panic");
    }
}
