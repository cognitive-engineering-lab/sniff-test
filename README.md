# sniff-test

`sniff-test` runs panic reachability analysis through Cargo. It wraps
`cargo check`, records panic evidence from rustc MIR, and reports undocumented
panic paths, documented panic contracts, and trusted panic-contract boundaries.

## Cargo Frontend

Use the Cargo subcommand for normal analysis:

```sh
cargo sniff-test [OPTIONS] [-- CARGO-ARGS]
```

The installed binary also supports direct invocation:

```sh
cargo-sniff-test [sniff-test] [OPTIONS] [-- CARGO-ARGS]
```

The optional `sniff-test` word is accepted because Cargo invokes subcommands as
`cargo-sniff-test sniff-test ...`.

Common options:

- `init`: write a sample `sniff-test.toml`
- `--manifest PATH`: path to `sniff-test.toml`
- `--cache-dir DIR`: analysis cache directory
- `--color auto|always|never`
- `--message-format human|json`
- `--overflow-checks on|off`
- `--build-std`
- `--release`

Arguments after `--` are passed to the wrapped `cargo check` command:

```sh
cargo sniff-test --release -- --features dangerous -p my-crate
```

`cargo sniff-test` exits with status `1` when a final workspace crate has
undocumented panic paths. Documented panic contracts and dependency-only raw
findings are reported, but do not by themselves fail the frontend command.

## JSON Output

Human output is written to stderr by default. For machine-readable output:

```sh
cargo sniff-test --message-format json
```

JSON mode writes newline-delimited messages to stdout, while Cargo and rustc
diagnostics stay on stderr. Each sniff-test message has
`"reason":"sniff-test-artifact"` and describes one analyzed artifact.

## Source Markers

Use `// SAFE: ...` in the contiguous standalone comment block immediately above
a call or compiler-checked expression when that specific site has been inspected
and the panic precondition is satisfied by a local invariant:

```rust
pub fn ratio(total: usize, denominator: usize) -> usize {
    // SAFE: caller guarantees denominator is nonzero.
    // The public constructor enforces that invariant.
    total / denominator
}
```

Marked edges are skipped for panic reachability. On function calls, this also
prevents sniff-test from descending into the callee through that call site.

## Direct Driver

`sniff-test-driver` is normally invoked by `cargo sniff-test` as a
`RUSTC_WRAPPER`. It can also be used directly for harness tests:

```sh
sniff-test-driver [RUSTC-ARGS] -- [SNIFF-TEST-ARGS]
```

Direct-mode sniff-test arguments:

- `--manifest PATH`
- `--cache-dir DIR`
- `--color auto|always|never`
- `--message-format human|json`

Cargo frontend options are intentionally rejected in direct mode. Put rustc
profile/codegen flags before the driver separator instead:

```sh
sniff-test-driver rustc src/lib.rs -C overflow-checks=on -- --message-format json
```

## Checks

Run the local verification suite with:

```sh
just check
```

JSON fixture checks are:

```sh
python3 scripts/check-json-fixtures.py
```

It runs the fixture crates listed in `tests/cases.toml`, normalizes JSON output,
and compares it with `tests/expected/*.json`.

CLI smoke checks are:

```sh
python3 scripts/check-cli-smoke.py
```

They check stable fragments of rustc-style output, including compact traces,
full-stack traces, dependency warning footers, Cargo argument forwarding, and
the absence of old summary lines.
