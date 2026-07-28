pub fn mixed_sources_share_one_marker() {
    // PANIC: the caller maintains the precondition for both effects.
    {
        dependency_cross_origin_ambiguity::cached_panic();
        panic!("local");
    }
}
