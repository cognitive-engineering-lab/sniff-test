# sniff-test

`sniff-test` finds effect paths inter-procedurally in Rust projects. It helps you document caller-visible effects and justify effects that are safe because of local invariants.

## Install
```sh
git clone https://github.com/cognitive-engineering-lab/sniff-test.git --branch refactor/sniff-test
cd sniff-test
cargo install --path crates/sniff-test
```

## Use

From the root of your Rust project, create the default configuration and run
the check:

```sh
cargo sniff-test init
cargo sniff-test
```

Use `-e` to select effect you want to check. Current supported options are `panic` and `safety` effects. By default, without `-e`, all supported effects wil be checked.

```sh
cargo sniff-test -e panic
```

Pass Cargo arguments after `--`:

```sh
cargo sniff-test -- --all-features
```

Run `cargo sniff-test --help` for options. See the [extended documentation](docs/README.md)
for configuration, output formats, analysis behavior, direct-driver usage, and
contributor commands.


## Effect Example
Use a `# Panics` section to document when callers may observe a panic, and a
`# Safety` section to document the requirements of a public unsafe API.


When a panic or unsafe operation is intentional, place a justification comment directly above it:

```rust
// PANIC: `denominator` was checked above and cannot be zero.
let ratio = total / denominator;

// SAFETY: `pointer` comes from a live reference and is properly aligned and non-null.
let value = unsafe { pointer.read() };
```

## Acknowledgments

See [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md).
