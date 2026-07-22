# sniff-test

`sniff-test` checks source-level effect contracts through Cargo. It wraps
`cargo check`, discovers panic effects from rustc MIR and safety effects from
THIR, then reports paths whose `# Panics`/`# Safety` obligations or
`// PANIC:`/`// SAFETY:` justifications are incomplete.

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

Common `sniff-test.toml` analysis knobs:

```toml
[analysis]
show-full-stack-trace = false
report-roots = "public"     # public | all | ["crate::path"]
overflow-checks = "profile" # profile | on | off
inline-mir = "off"          # profile | on | off
callable-edge-attribution = "erasure-sites" # erasure-sites | call-sites
marker-probing = "macro-definition-first" # macro-definition-first | source-callsite

[analysis.lints]
analysis-incomplete = "deny"
ambiguous-effect-marker = "deny" # deny | warn | allow
ambiguous-effect-requirement = "deny"
empty-report-roots = "warn"
missing-report-root = "warn"

[documentation]
override-files = [] # TOML files relative to sniff-test.toml

[panics.lints]
compiler-assert = "deny"
panic-invocation = "deny"
cached-dependency-panic = "deny"
documented-panic = "warn"
trusted-panic = "warn"
indirect-call-boundary = "warn"

[safety]
ignored-namespaces = []
safety-obligation-namespaces = []

[safety.lints]
missing-safety-docs = "warn"
unsafe-call-missing-justification = "warn"
unsafe-call-missing-requirements = "warn"
unsafe-op-missing-justification = "warn"
safety-obligation-missing-justification = "warn"
safety-obligation-missing-requirements = "warn"
```

`inline-mir = "off"` passes `-Z inline-mir=no`, which keeps panic traces closer
to the source call structure.

`callable-edge-attribution = "erasure-sites"` reports concrete callable targets
where a function item, closure, or concrete type is erased into an indirect
callable such as a `fn` pointer or `dyn Trait`. `call-sites` reports concrete
function-pointer targets and dynamic-dispatch vtable methods at the call span
instead of the erasure span. Call-site attribution uses shared, type-keyed
evidence: function-pointer reifications with the same `fn` pointer type, or
concrete values cast to the same dyn trait, may cause each matching call site
to connect to every target observed by the shared reachability index.

The two `ambiguous-effect-*` lints apply uniformly to panic and safety markers
and to duplicate normalized requirement names. `warn` accepts the ambiguity
but reports it; `allow` accepts it silently.

`marker-probing = "macro-definition-first"` lets `// PANIC:` and `// SAFETY:`
markers inside macro definitions satisfy operations produced by that macro,
then falls back through macro callsites to the outer source callsite.
`source-callsite` keeps lookup at the final user callsite only.

`report-roots` scopes both analyses. Effects propagate through reachable local
functions until a matching documented obligation or ignored namespace stops
the path. With `"public"`, a private helper is reported through the public root
that reaches it; with `"all"`, the helper can also receive its own finding.
Safety probing covers runtime function, method, closure, and coroutine bodies;
const, static, and inline-const initializers are intentionally outside this
runtime effect graph.

`cargo sniff-test` exits with status `1` when a final workspace crate has a
finding whose configured lint level is `deny`. `allow` suppresses a finding from
human diagnostics and JSON output; `warn` reports it without failing the run.

Use `[safety].safety-obligation-namespaces` for safe functions that still carry
caller obligations. Calls to matching functions must have a nearby `// SAFETY:`
justification, and named bullets under a callee `# Safety` section must be
satisfied by matching named bullets at the call site.

Use `[documentation].override-files` while auditing generated or third-party
APIs whose documented behavior is known but not written in source yet. Override files are
TOML files keyed by Rust namespace globs; the value replaces that function's
rustdoc markdown for both panic and safety documentation parsing. The markdown is
parsed as CommonMark, so normal headings, setext headings, inline code, and
formatted list text work as expected.

```toml
[overrides]
"zerocopy::Layout::for_type" = """
# Panics

- representable: layout size must fit in `usize`.
"""
```

## JSON Output

Human output is written to stderr by default. For machine-readable output:

```sh
cargo sniff-test --message-format json
```

JSON mode writes newline-delimited messages to stdout, while Cargo and rustc
diagnostics stay on stderr. Each sniff-test message has
`"reason":"sniff-test-artifact"` and describes one analyzed artifact.

## Source Markers

Use `// PANIC: ...` in the contiguous standalone comment block immediately above
a call or compiler-checked expression when that specific site has been inspected
and the panic precondition is satisfied by a local invariant:

```rust
pub fn ratio(total: usize, denominator: usize) -> usize {
    // PANIC: caller guarantees denominator is nonzero.
    // The public constructor enforces that invariant.
    total / denominator
}
```

For callees with named `# Panics` requirements, satisfy each requirement by
name:

```rust
/// # Panics
///
/// Panics when any listed requirement is violated.
///
/// Requirements:
///
/// - nonzero: denominator must not be zero.
/// - bounded[total]: total must be bounded by the caller.
pub fn ratio(total: usize, denominator: usize) -> usize {
    total / denominator
}

pub fn checked_ratio(total: usize, denominator: usize) -> usize {
    // PANIC:
    // The caller validates the documented panic conditions before this call.
    // Requirements:
    // - nonzero: caller checked the denominator.
    // - bounded[total]: caller checked the total bound.
    ratio(total, denominator)
}
```

The accepted requirement bullet format is `- name: condition`; rustdoc
conditions may be empty when the name is enough, but call-site satisfaction
bullets must include justification text. Names are matched case-insensitively,
with punctuation and whitespace treated as separators, so `bounded[total]` and
`bounded total` match. Duplicate names inside one documentation section are ambiguous under
the `ambiguous-effect-requirement = "deny"` policy: a single marker bullet
cannot prove two distinct requirements with the same normalized name. Prose and
labels such as `Requirements:` are allowed before the first bullet. Plain
comment lines following a requirement bullet in the same contiguous block are
kept as explanation context. Use `/// # Panics` to document public API panic behavior;
`// PANIC:` is only for local call-site justifications.

`// PANIC:` can also sit immediately above an enclosing block. A marker reused
by multiple panic sites is ambiguous. For safety, one explicit unsafe block is
one effect group, so a single `// SAFETY:` marker can justify all operations in
that block; reuse across distinct groups is ambiguous. Each callee still checks
its own named requirements.

## Direct Driver

`sniff-test-driver` is normally invoked by `cargo sniff-test` as a
`RUSTC_WRAPPER`. It can also be used directly for harness tests:

```sh
sniff-test-driver [SNIFF-TEST-ARGS] -- [RUSTC-ARGS]
```

Direct-mode sniff-test arguments:

- `--manifest PATH`
- `--cache-dir DIR`
- `--color auto|always|never`
- `--message-format human|json`

Cargo frontend options are intentionally rejected in direct mode. Put rustc
profile/codegen flags after the driver separator instead:

```sh
sniff-test-driver --message-format json -- src/lib.rs -C overflow-checks=on
```

Direct driver mode follows rustc-driver exit semantics: it returns success when
rustc succeeds, even if sniff-test emits findings. Use the Cargo frontend for
final workspace aggregation and deny-level effect gating.

## Checks

Run the local verification suite with:

```sh
just check
```

Fixture checks are:

```sh
just fixtures
```

The Rust test target defines one macro-generated test per fixture case. Cases
are grouped first by input domain, such as dyn dispatch, panic axioms,
dependencies, markers, or safety requirements. Each case then names the
sniff-test behavior under test, such as raw panic reporting, documented
obligations, trusted boundaries, or marker satisfaction. Each test copies its
fixture crate, normalizes JSON output, and compares it with cargo-insta
snapshots.

To run one fixture case:

```sh
just fixture panic_axioms
```

To update and review snapshot changes with `cargo-insta`:

```sh
just fixtures-review
just fixtures-accept
```

CLI diagnostic snapshots are:

```sh
just cli
```

They snapshot normalized rustc-style output, including compact traces,
full-stack traces, dependency warning footers, SAFETY diagnostics, Cargo
argument forwarding, and flat effect findings.

Run all snapshot tests with stale-snapshot rejection via:

```sh
just snapshots
```

## Acknowledgments

The `reachability` crate's methodology was informed by
[Ferrocene](https://github.com/ferrocene/ferrocene), a downstream of the Rust
compiler maintained by Ferrous Systems. Its implementation evolved from the
original sniff-test reachability modules and has since been substantially
rewritten. See [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md) for details.
