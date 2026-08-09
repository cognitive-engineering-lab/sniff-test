pub fn division(total_size: usize, block_count: usize) -> usize {
    total_size / block_count
}

pub fn remainder(total_size: usize, block_size: usize) -> usize {
    total_size % block_size
}

pub fn indexed(values: &[usize], index: usize) -> usize {
    values[index]
}
