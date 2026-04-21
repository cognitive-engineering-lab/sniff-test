#![sniff_tool::check_unsafe_pub]
#![sniff_tool::check_panics_pub]

// Clippy doesn't catch any of these!
// #![deny(
//     clippy::undocumented_unsafe_blocks,
//     clippy::missing_safety_doc,
//     clippy::missing_panics_doc
// )]

pub fn main() {}

pub fn chunk_slice(slice: &[usize], chunk_size: usize) -> Vec<&[usize]> {
    // META: this would be a good case where the obligation gets propagated up to callers
    let num_chunks = slice.len() / chunk_size;

    // META: this is an example of a place where we can discharge the obligation here.
    let mut result = Vec::with_capacity(num_chunks);

    let mut start = 0;
    for _ in 0..num_chunks {
        let chunk = &slice[start..(start + chunk_size)];
        // META: this is an example of a place where we can discharge the obligation here.
        result.push(chunk);
        start += chunk_size;
    }

    result
}
