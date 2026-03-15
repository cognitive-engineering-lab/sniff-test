# Testing

To accept all new snapshots, run `INSTA_UPDATE=always cargo test` or to accept only for new tests, run `INSTA_UPDATE=unseen cargo test`.

## Directly invoking the sniff-test driver
`RUST_LOG="sniff_test=debug" CARGO_TERM_COLOR="never" PLUGIN_ARGS="{\"dependencies\":\"Trust\",\"check_dependencies\":false,\"fine_grained\":false,\"buzzword_checking\":false,\"cargo_args\":[]}" RUSTC_PLUGIN_ALL_TARGETS="" RUSTC_WORKSPACE_WRAPPER="" "/Users/alexanderportland/Desktop/research/sniff-test/target/release/sniff-test-driver" "--extern" "sniff_test_attrs=../target/release/libsniff_test_attrs.dylib" "-Zcrate-attr=feature(register_tool)" "-Zcrate-attr=register_tool(sniff_tool)" "-Zcrate-attr=feature(custom_inner_attributes)" "-Zno-codegen" /Users/alexanderportland/Desktop/research/sniff-test/tests/panics/01_unused.rs`