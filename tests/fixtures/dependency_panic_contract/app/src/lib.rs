pub fn justifies_raw_panic() {
    // PANIC: the caller maintains the dependency invariant.
    dependency_panic_contract::raw_panic();
}

pub fn unnamed_marker_misses_requirement() {
    // PANIC: this does not name the dependency's nonzero requirement.
    dependency_panic_contract::misses_named_requirement();
}

pub fn named_marker_satisfies_requirement() {
    // PANIC:
    // - nonzero: the application checked the value.
    dependency_panic_contract::misses_named_requirement();
}

pub fn ambiguous_marker(left: bool, right: bool) {
    // PANIC: the caller maintains both dependency invariants.
    dependency_panic_contract::two_raw_panics(left, right);
}

pub fn completes_cached_requirements() {
    // PANIC:
    // - exclusive: this call runs before worker threads start.
    dependency_panic_contract::partially_satisfies_requirements();
}

pub fn leaves_cached_requirement_unsatisfied() {
    dependency_panic_contract::partially_satisfies_requirements();
}
