#![feature(rustc_private)]

fn main() {
    sniff_test::env_logger_init(true);
    rustc_plugin::driver_main(sniff_test::PrintAllItemsPlugin);
}
