pub fn partially_satisfies_requirements() {
    // SAFETY:
    // - initialized: the application initialized the global state.
    partial_effect_requirements::misses_both_requirements();
}
