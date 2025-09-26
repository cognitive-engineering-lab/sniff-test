# Usage notes

You should be able to just run this using `cargo build` and then running the resulting `cargo-sniff-test` binary within the crate you'd like to analyze. [We should add instructions for installing to cargo path later.]

### Linking error

If you encounter an error along the lines of `dyld[43663]: Library not loaded: ...`, run:
```shell
export DYLD_LIBRARY_PATH="$DYLD_LIBRARY_PATH:$(rustc +nightly-2025-08-20 --print target-libdir)"
```


you can run the jawn with 
```rust
cargo clean && RUSTFLAGS="-Zcrate-attr=feature(register_tool) -Zcrate-attr=register_tool(sniff_tool)" /Users/alexanderportland/Desktop/research/sniff-test/target/debug/cargo-sniff-test
```