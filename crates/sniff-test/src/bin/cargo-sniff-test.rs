#![feature(rustc_private)]

fn main() {
    sniff_test::env_logger_init(false);
    rustc_plugin::cli_main(sniff_test::PrintAllItemsPlugin);
}
