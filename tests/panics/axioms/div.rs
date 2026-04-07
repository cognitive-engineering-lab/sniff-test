extern crate sniff_test_attrs;

fn block_sz(total_size: usize, block_count: usize) -> usize {
    total_size / block_count
}

#[sniff_test_attrs::check_panics]
fn main() {
    block_sz(100, 0);
}
