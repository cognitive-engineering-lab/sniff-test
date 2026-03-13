trait Foo {
    /// # Panics
    /// - i-valid-radix: panics if i is no a valid radix (between 1-36)
    // TODO: potential no panics annotation, but for now, traits are a special case
    // where not having panic annotation doesn't mean there's an obligation for implementors
    // std library trust that no panics docs -> no panicking
    // * goal to fit to what can be used
    fn do_foo(i: u32) -> i32;
}

#[sniff_tool::check_panics] // <- sniff test cannot reasonably build a call-graph for this if Foo is exported
pub fn calls_f(f: impl Foo) -> i32 {
    /// PANICS:
    /// - 3 is trivially between 1-36 and thus a valid radix for i.
    f.do_foo(3)
}

// TODO: two specific heuristics
// 1. if a function is named as a generic in a function add an edge
// 2. static method resolution <- if you call through calls_f, make sure you're
// getting the right method

// if a trait def has explicit documentation, take it at it's word
