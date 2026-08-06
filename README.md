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
- `--debug`: analyze debug-profile MIR instead of the default release profile

An explicit Cargo `--profile` argument after `--` overrides the default release
profile.

Arguments after `--` are passed to the wrapped `cargo check` command:

```sh
cargo sniff-test -- --features dangerous -p my-crate
```

Common `sniff-test.toml` knobs:

```toml
[compiler]
overflow-checks = "profile" # profile | on | off
inline-mir = "off"          # profile | on | off

[analysis]
show-full-stack-trace = false
report-roots = "public"     # public | all | ["crate::path"]
callable-edge-attribution = "erasure-sites" # erasure-sites | call-sites
marker-probing = "macro-definition-first" # macro-definition-first | source-callsite

[analysis.lints]
panic-analysis-incomplete = "deny"
safety-analysis-incomplete = "deny"
# Optional overrides when a reached managed dependency body is missing:
# dependency-panic-analysis-incomplete = "warn"
# dependency-safety-analysis-incomplete = "warn"
ambiguous-panic-marker = "deny" # deny | warn | allow
ambiguous-safety-marker = "deny"
ambiguous-panic-requirement = "deny"
ambiguous-safety-requirement = "deny"
empty-report-roots = "warn"
missing-report-root = "warn"

[documentation]
override-files = [] # TOML files relative to sniff-test.toml

[panics]
trusted-panic-boundary-namespaces = []

[panics.lints]
# Group default for compiler-generated MIR assertions.
compiler-assert = "deny"
# Optional exact overrides:
# compiler-assert-bounds-check = "deny"
# compiler-assert-overflow = "deny"
# compiler-assert-overflow-negation = "deny"
# compiler-assert-division-by-zero = "deny"
# compiler-assert-remainder-by-zero = "deny"
# compiler-assert-resumed-after-return = "deny"
# compiler-assert-resumed-after-panic = "deny"
# compiler-assert-resumed-after-drop = "deny"
# compiler-assert-misaligned-pointer-dereference = "deny"
# compiler-assert-null-pointer-dereference = "deny"
# compiler-assert-invalid-enum-construction = "deny"
panic-invocation = "deny"
documented-panic = "warn"
trusted-panic = "warn"
indirect-call-boundary = "warn"

[safety]
ignored-namespaces = []
trusted-safety-boundary-namespaces = []

[safety.lints]
missing-safety-docs = "warn"
unsafe-call-missing-justification = "warn"
unsafe-call-missing-requirements = "warn"
# Group default for non-call unsafe operations.
unsafe-op-missing-justification = "warn"
# Optional exact overrides:
# raw-pointer-dereference-missing-justification = "warn"
# mutable-static-access-missing-justification = "warn"
# extern-static-access-missing-justification = "warn"
# union-field-access-missing-justification = "warn"
# unsafe-field-access-missing-justification = "warn"
# layout-constrained-type-initialization-missing-justification = "warn"
# unsafe-field-initialization-missing-justification = "warn"
# layout-constrained-field-mutation-missing-justification = "warn"
# layout-constrained-field-borrow-missing-justification = "warn"
# inline-assembly-missing-justification = "warn"
# unsafe-binder-cast-missing-justification = "warn"
safety-obligation-missing-justification = "warn"
safety-obligation-missing-requirements = "warn"
```

`[compiler].inline-mir = "off"` passes `-Z inline-mir=no`, which keeps panic
traces closer to the source call structure. Compiler settings are applied
literally and independently from lint policy. For example, disabling overflow
checks does not change or reject `[panics.lints].compiler-assert-overflow`.

The v14 analysis cache stores policy-neutral artifact IR: function identities,
call edges, raw compiler assertions and unsafe operations, source markers,
contracts, and verified file-relative source ranges. It does not store selected
report roots, lint levels, interpreted findings, or rendered traces.
Dependency rustc units extract every analyzable body and silently persist this
IR; they do not select roots, interpret policy, emit diagnostics, or write JSON
reports. Workspace units select `[analysis].report-roots`, compose local IR with
verified dependency IR, interpret only the reachable combined graph, and emit
the workspace findings. Unreachable dependency IR therefore produces no
findings.

For concrete cross-crate generic calls, the consuming rustc unit also stores an
exact-instantiation overlay. This preserves dispatch selected using a
workspace-local type while the defining dependency cache remains generic and
policy-neutral. The frontend ensures dependency metadata contains the MIR
needed to build these overlays.

Loadable caches use rustc's own exact artifact identity: the stable crate ID
plus strict version hash (SVH). Cache filenames are
`artifacts/<stable-crate-id>-<svh>.json`; Cargo output suffixes and crate names
are not used as identity. Compiler settings that affect the crate are already
reflected in rustc's SVH, while lint and other interpretation-only changes
reuse the same dependency IR. Workspace executable IR, for which rustc does not
produce an SVH, is interpreted in memory rather than assigned a synthetic cache
identity. Failure to produce, validate, or persist required dependency IR is a
tool error rather than a successful run with partial dependency analysis.
Because rustc excludes ordinary comments from the SVH, available source files
that contributed `// PANIC:` or `// SAFETY:` marker facts are content-verified
before those facts are interpreted.

`callable-edge-attribution = "erasure-sites"` reports concrete callable targets
where a function item, closure, or concrete type is erased into an indirect
callable such as a `fn` pointer or `dyn Trait`. `call-sites` reports concrete
function-pointer targets and dynamic-dispatch vtable methods at the call span
instead of the erasure span. Call-site attribution uses type-keyed evidence
reached while interpreting each selected root: function-pointer reifications
with the same `fn` pointer type, or concrete values cast to the same dyn trait,
may cause matching reachable call sites to connect to every target reached from
that root. Dependency caches store only raw erasure, invocation, and key facts;
they do not pre-resolve callable targets for any workspace policy or root set.

The older `ambiguous-effect-marker`, `ambiguous-effect-requirement`, and
`analysis-incomplete` keys remain accepted as group defaults for both effect
domains. An explicit panic- or safety-specific key takes precedence over its
group default regardless of TOML ordering. `warn` accepts the ambiguity
but reports it; `allow` accepts it silently.

`dependency-panic-analysis-incomplete` and
`dependency-safety-analysis-incomplete` are optional overrides for a reached
managed dependency body that is absent from the composed artifact graph.
Without an exact dependency override, the corresponding
`panic-analysis-incomplete` or `safety-analysis-incomplete` level applies.
These overrides do not apply to the workspace traversal's node limit.

Likewise, exact `compiler-assert-*` overrides take precedence for assertions
regardless of which artifact supplied the raw fact. Without an exact override,
all compiler assertions use `compiler-assert`.
`unsafe-op-missing-justification` is the fallback for every exact non-call
unsafe-operation key. JSON reports retain the broad `kind` and add
`compiler-assert-kind` or `safety-op-kind`, so the selected subtype remains
machine-readable.

`marker-probing = "macro-definition-first"` lets `// PANIC:` and `// SAFETY:`
markers inside macro definitions satisfy operations produced by that macro,
then falls back through macro callsites to the outer source callsite.
`source-callsite` keeps lookup at the final user callsite only.

`report-roots` controls workspace traversal and reporting, not artifact
extraction. Effects propagate from each selected workspace root through local
and cached dependency functions until a documented contract, trusted boundary,
or ignored namespace stops the path. With `"public"`, a private helper is
reported through the public root that reaches it; with `"all"`, the helper can
also receive its own finding.
Safety probing covers runtime function, method, closure, and coroutine bodies;
const, static, and inline-const initializers are intentionally outside this
runtime effect graph. Coroutine construction conservatively makes its stored
runtime body reachable; merely constructing an async closure does not, until
that callable is invoked.

`cargo sniff-test` exits unsuccessfully when a workspace crate has a finding
whose configured lint level is `deny`. `allow` suppresses a finding from human
diagnostics and JSON output; `warn` reports it without failing the run.

Use `[panics].trusted-panic-boundary-namespaces` for audited APIs whose
`# Panics` documentation is authoritative. Every match is opaque. Documented
conditions become caller obligations; an undocumented match is trusted as
non-panicking. A broad glob therefore asserts that the matched library
documents every caller-visible panic condition.

Use `[safety].trusted-safety-boundary-namespaces` for audited APIs whose
`# Safety` documentation is authoritative. Documented requirements must be
satisfied by nearby `// SAFETY:` markers; an undocumented match is trusted as
carrying no safety obligation, even when declared `unsafe`. Matching
implementations remain opaque.

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
diagnostics stay on stderr. Only workspace rustc units emit sniff-test messages;
dependency units cache IR silently. Each workspace unit emits at most one
message with `"reason":"sniff-test-artifact"`. Reports have no dependency
`scope`, cache identity, or dependency list because every public report is a
workspace report.
sniff-test records an invocation token only in workspace dep-info, so Cargo
reruns report-producing workspace units on every invocation to reinterpret and
validate cached IR while leaving otherwise-fresh dependency units untouched.

When a finding originated in cached dependency IR, sniff-test loads its recorded
source file into rustc's active source map only after verifying the stable file
identity, exact content hash, normalized byte length, and byte range. If source
is missing or no longer matches, the finding remains reportable but degrades to
an unspanned diagnostic instead of pointing at unverified text.

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
the effect-specific `ambiguous-panic-requirement = "deny"` or
`ambiguous-safety-requirement = "deny"` policy: a single marker bullet
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
- `--dependency` to cache this manually compiled upstream unit silently

Cargo frontend options are intentionally rejected in direct mode. Put rustc
profile/codegen flags after the driver separator instead:

```sh
sniff-test-driver --message-format json -- src/lib.rs -C overflow-checks=on
```

Standalone invocations are report-producing workspace units by default and do
not depend on Cargo's `CARGO_PRIMARY_PACKAGE` environment variable. When
manually building a dependency before its consumer, pass `--dependency` for
that upstream rustc unit so it persists complete IR without diagnostics or a
JSON report.

Direct driver mode follows rustc-driver exit semantics: it returns success when
rustc succeeds, even if sniff-test emits findings. Required IR extraction or
cache persistence failures are tool errors. Use the Cargo frontend for
deny-level effect gating.

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
full-stack traces, verified cached-source snippets and fallback notes, SAFETY
diagnostics, Cargo argument forwarding, and flat effect findings.

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
