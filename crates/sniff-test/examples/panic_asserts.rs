#![allow(clippy::must_use_candidate)]

pub fn block_size(total_size: usize, block_count: usize) -> usize {
    total_size / block_count
}

pub fn block_remainder(total_size: usize, block_size: usize) -> usize {
    total_size % block_size
}

pub fn read_at(values: &[i32], index: usize) -> i32 {
    values[index]
}

pub fn assert_examples(values: &[i32], index: usize, block_count: usize) -> i32 {
    let size = block_size(values.len(), block_count);
    let remainder = block_remainder(values.len(), block_count);
    read_at(values, index) + i32::try_from(size + remainder).unwrap_or(0)
}

fn main() {
    let values = [1, 2, 3];
    let _ = assert_examples(&values, 1, 2);
}
