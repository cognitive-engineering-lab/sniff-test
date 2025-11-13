use std::thread;
use std::time::Duration;

#[sniff_test_attrs::check_unsafe]
fn main() {
    thread::sleep(Duration::from_millis(100));
}
