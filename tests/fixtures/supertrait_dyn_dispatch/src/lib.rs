pub trait Super {
    fn risky(&self, flag: bool);
}

pub trait Sub: Super {
    fn calm(&self) {}
}

pub struct Widget;

impl Super for Widget {
    fn risky(&self, flag: bool) {
        assert!(flag, "flag must be set");
    }
}

impl Sub for Widget {}

pub fn call_supertrait_method(flag: bool) {
    let object: &dyn Sub = &Widget;
    object.risky(flag);
}
