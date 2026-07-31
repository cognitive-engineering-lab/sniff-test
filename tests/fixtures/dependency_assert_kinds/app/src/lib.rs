pub fn divide_dependency(value: usize, divisor: usize) -> usize {
    dependency_assert_kinds::divide(value, divisor)
}

pub fn index_dependency(values: &[usize], index: usize) -> usize {
    dependency_assert_kinds::index(values, index)
}
