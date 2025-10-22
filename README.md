# Sniff-test

## Running
You can run `sniff-test` with the following command once it's been built using `cargo build` (just replace `PATH_TO_REPO` with the directory in which you installed this repo).
*[We should add instructions for installing to cargo path later.]*

```shell
cargo build # in this directory

cd [PATH_TO_TEST_CRATE]

cargo clean && RUSTFLAGS="-Zcrate-attr=feature(register_tool) -Zcrate-attr=register_tool(sniff_tool)" [PATH_TO_REPO]/sniff-test/target/debug/cargo-sniff-test
```

We need the extra `RUSTFLAGS` to register our `sniff_tool` tool to allow for our custom attributes.

### Linking error

If you encounter an error along the lines of `dyld[43663]: Library not loaded: ...`, run:

```shell
export DYLD_LIBRARY_PATH="$DYLD_LIBRARY_PATH:$(rustc +nightly-2025-08-20 --print target-libdir)"
```

## Testing

As of now, we have the infrastructure to use `cargo-insta` for snapshot testing, but there's not enough functionality for it to be particularly useful yet.

### Taking snapshots
Using `cargo insta test`, you can snapshot all of our test crates, saving all new snapshots within each of the crates.
This will run the [`cargo-sniff-test`](/crates/sniff-test/src/bin/cargo-sniff-test.rs) binary on every crate within a subdirectory of [`tests`](/tests).

By default, `cargo insta review` will only look through the current workspace to find new snapshots, but ours test crates have to be in separate workspaces to not all compile together.
Instead, now the testing infrastructure automatically builds a [`review.sh`](/review.sh) script that will review all of the test crates together.

```shell
cargo insta test # snapshot all tests
./review.sh      # review new snapshots

cargo test       # run all tests (no new snapshots)
```