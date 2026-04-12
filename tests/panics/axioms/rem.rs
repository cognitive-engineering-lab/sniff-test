extern crate sniff_test_attrs;

fn block_rem(total_size: usize, block_size: usize) -> usize {
    total_size % block_size
}

#[sniff_test_attrs::check_panics]
fn main() {
    block_rem(100, 0);
}
