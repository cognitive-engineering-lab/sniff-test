pub fn satisfies_only_one_cached_requirement() {
    // SAFETY:
    // - initialized: the application initialized the global state.
    dependency_safety_partial_requirements::misses_both_requirements();
}
