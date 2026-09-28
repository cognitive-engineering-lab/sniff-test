pub fn call_through_closure() {
    closure_dependency::map(|x| closure_dependency::documented(x));
}

pub fn call_through_function_item() {
    closure_dependency::map(closure_dependency::documented);
}
