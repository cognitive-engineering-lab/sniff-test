// Cross-crate instantiations must retain the defining closure's source facts,
// even when the generic parent's call cannot resolve in the dependency.
pub fn check_value<T>(value: Option<T>) -> Option<T> {
    let closure = || {
        assert!(value.is_some(), "dependency closure");
        value
    };
    closure()
}

pub fn justified<T>(value: Option<T>) -> Option<T> {
    let closure = || {
        // PANIC: The caller supplies a present value.
        assert!(value.is_some(), "justified dependency closure");
        value
    };
    closure()
}

pub fn read_pointer<T: Copy>(pointer: *const T) -> T {
    let closure = || {
        unsafe { *pointer }
    };
    closure()
}

// Both FnOnce bodies capture generic state and need defining-artifact facts.
pub fn nested<T>(value: Option<T>) -> Option<T> {
    let outer = move || {
        let inner = move || {
            assert!(value.is_some(), "nested dependency closure");
            value
        };
        inner()
    };
    outer()
}

// The closure escapes the dependency and is called as FnMut by the consumer.
pub fn make_consumer<T>(mut value: Option<T>) -> impl FnMut() -> Option<T> {
    move || {
        assert!(value.is_some(), "returned dependency closure");
        value.take()
    }
}

pub trait Action {
    fn run(&self);
}

// Generic source facts must not replace the concrete consumer's trait target.
pub fn dispatch<T: Action>(value: T) -> impl Fn() {
    move || value.run()
}

pub fn nested_read<T: Copy>(value: &T) -> T {
    let pointer = value as *const T;
    // SAFETY: The pointer comes from a live reference and is read synchronously.
    unsafe {
        let outer = || {
            let inner = || *pointer;
            inner()
        };
        outer()
    }
}
