pub fn call_incomplete_dependency(flag: bool) {
    // PANIC: the caller proves the dependency's known assertion.
    dependency_panic_incomplete_resolved::incomplete_with_known_panic(flag);
}
