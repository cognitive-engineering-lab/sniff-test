use dyn_dispatch_dep::{Runner, drive};

struct Risky(*const u8);
impl Runner for Risky {
    fn run(&self) {
        let _value = unsafe { *self.0 };
        panic!("selected implementation");
    }
}

pub fn unresolved(value: &dyn Runner) { drive(value); }
pub fn justified() { dyn_dispatch_dep::justified(&Risky(&0)); }
pub fn propagated() { dyn_dispatch_dep::propagated(&Risky(&0)); }
fn main() { drive(&Risky(&0)); }
