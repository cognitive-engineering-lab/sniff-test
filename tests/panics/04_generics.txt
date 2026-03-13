trait Foo {
    fn do_foo() -> i32;
}

#[sniff_tool::check_panics] // <- sniff test cannot reasonably build a call-graph for this if Foo is exported
// TODO: So warn if entrypoints have generics for public traits?
// TODO: or have multiple ways of dealing with traits?
//       -> the current method would say that all implementations of Foo must be monolithic and either all panic or not panic
pub fn calls_f(f: impl Foo) -> i32 {
    f.do_foo()
}
