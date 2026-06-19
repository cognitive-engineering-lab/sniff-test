pub fn generic_index<T>(values: &[T], index: usize) -> &T {
    &values[index]
}

pub fn generic_split_at<T>(values: &[T], index: usize) -> &[T] {
    values.split_at(index).0
}
