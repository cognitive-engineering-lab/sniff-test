trait Fn<Args, Res> {
    fn call(&self, args: Self::Args) -> Self::Res;
}

#[sniff_tool::check_panics]
pub fn calls_f(f: impl Fn<(), i32>) -> i32 {
    f.call(3)
}

// TODO: this scheme seems to make muchhhh less sense here
// audience: library developers who haven't thought about panics & people using libraries they dont trust
// look for asserts in MIR
//
