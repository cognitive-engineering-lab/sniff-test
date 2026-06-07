#![allow(clippy::must_use_candidate)]

pub fn chunk_slice(slice: &[usize], chunk_size: usize) -> Vec<&[usize]> {
    let num_chunks = slice.len() / chunk_size;
    let mut chunks = Vec::with_capacity(num_chunks);

    let mut start = 0;
    for _ in 0..num_chunks {
        let end = start + chunk_size;
        chunks.push(&slice[start..end]);
        start = end;
    }

    chunks
}

fn main() {
    let values = [1, 2, 3, 4];
    let _ = chunk_slice(&values, 2);
}
