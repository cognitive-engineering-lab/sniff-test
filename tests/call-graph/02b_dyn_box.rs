#[sniff_tool::check_panics]
fn main() {
    let panics: std::boxed::Box<dyn Fn() -> i32> = std::boxed::Box::new(|| panic!());
    calls_f(panics);
}

// FALSE NEGATIVE: similarly, if you use dynamic dispatch with function traits, type erasure can mean we won't
// be able to determine the source of a closure based on just type. This is functionally equivalent to
// the previous example with a fn pointer type, but TODO: it begs the question of if we can have a unified response
// to the fn traits as if they're just any other traits.
fn calls_f(f: Box<dyn Fn() -> i32>) -> i32 {
    f()
}

// TODO: be on the lookout for weird control flow patterns to make sure our call graph
// construction can handle them (like bevy)
