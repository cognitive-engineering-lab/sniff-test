pub fn partially_satisfies_requirements() {
    // SAFETY:
    // - initialized: the application initialized the global state.
    partial_effect_requirements::misses_both_requirements();
}

fn satisfies_initialized_requirement() {
    // SAFETY:
    // - initialized: the application initialized the global state.
    partial_effect_requirements::misses_both_requirements();
}

pub fn composes_requirement_satisfactions() {
    // SAFETY:
    // - exclusive: this call runs before worker threads start.
    satisfies_initialized_requirement();
}

pub fn preserves_complementary_path_requirements() {
    // SAFETY:
    // - initialized: the application initialized the global state.
    partial_effect_requirements::complementary_paths();
}
