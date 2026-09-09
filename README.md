# sniff-test

`sniff-test` checks source-level effects through Cargo. It wraps `cargo check`
and traces three equal, first-class effects: panic sources from rustc MIR,
safety sources from rustc THIR, and documentation obligations from
`# Panics`/`# Safety` contracts. Each effect propagates toward callers over
source-level invocations and terminates according to its own contract or
justification rules.

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

Commands and common options:

- `init`: write a sample `sniff-test.toml`
- `--manifest PATH`: path to `sniff-test.toml`
- `-e EFFECT`, `--effect EFFECT`: track only `panic` or `safety`; repeat to select both
- `--cache-dir DIR`: analysis cache directory
- `--color auto|always|never`
- `--message-format human|json`
- `--overflow-checks profile|on|off`
- `--build-std`
- `--debug`: analyze debug-profile MIR instead of the default release profile

Without `--effect`, sniff-test tracks both panic and safety effects. Selecting
one domain skips extraction, probing, tracing, and diagnostics for the other.

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
marker-probing = "macro-definition-first" # macro-definition-first | source-callsite
effect-doc-matching = "any-justification" # any-justification | exact
max-trace-depth = 256
trace-state-budget = 1000000

[analysis.lints]
# These policies apply regardless of which artifact supplied the reached body.
panic-analysis-incomplete = "deny"
safety-analysis-incomplete = "deny"
ambiguous-panic-marker = "deny" # deny | warn | allow
ambiguous-safety-marker = "deny"
ambiguous-panic-requirement = "deny"
ambiguous-safety-requirement = "deny"
empty-report-roots = "warn"
missing-report-root = "warn"

[contracts]
override-files = [] # TOML files relative to sniff-test.toml

[panics]
ignored-namespaces = [
    "core::ub_checks::assert_unsafe_precondition",
]
trusted-boundary-namespaces = ["core", "alloc", "std"]

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
unresolved-call-target = "allow"

[safety]
ignored-namespaces = []
trusted-boundary-namespaces = ["core", "alloc", "std"]

[safety.lints]
missing-safety-docs = "warn"
unresolved-call-target = "allow"
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

The analysis cache uses format version 23 and stores one direct,
policy-neutral fact schema: function identities, source-level invocations,
compiler-assert kinds, unsafe operations, annotations, contracts, and verified
file-relative source ranges, plus workspace/dependency artifact ownership. It
does not persist traversal state, selected
report roots, lint levels, interpreted findings, or rendered traces.
Target-code dependency rustc units extract every analyzable body and silently
persist these facts. Build scripts and proc-macro units are skipped; target code
generated by a proc macro is analyzed in the consuming crate. Successful
dependency units do not select roots, interpret policy, emit finding diagnostics,
or write JSON reports. Workspace units select
`[analysis].report-roots`, compose local facts with verified dependency facts,
interpret only the reachable combined graph, and emit the workspace findings.
Unreachable dependency facts therefore produce no findings.

For concrete cross-crate generic calls, the consuming rustc unit also stores an
exact-instantiation overlay. This preserves dispatch selected using a
workspace-local type while the defining dependency cache remains generic and
policy-neutral. The frontend ensures dependency metadata contains the MIR
needed to build these overlays.

Loadable caches use rustc's own exact artifact identity: the stable crate ID
plus strict version hash (SVH). Cache filenames are
`artifacts/<stable-crate-id>-<svh>.json`; Cargo output suffixes and crate names
are not used as identity. Compiler settings that affect the crate are already
reflected in rustc's SVH, while lint and other interpretation-only settings
reuse the same dependency facts. Workspace outputs that are not loadable as
crates, including executable-only units, are interpreted in memory and are not
assigned cache identities. Failure to produce, validate, or persist required
dependency analysis facts is a tool error rather than a successful run with partial
dependency analysis.
Because rustc excludes ordinary comments from the SVH, available source files
that contributed `// PANIC:` or `// SAFETY:` marker facts are content-verified
before those facts are interpreted.

Callable dispatch follows rustc's resolution for the invocation being analyzed.
When rustc resolves a concrete implementation, sniff-test traces that
implementation and uses its domain contract, falling back to the corresponding
trait declaration contract when the implementation has none. When an
implementation remains unresolved, an available trait or interface declaration
contract is the only caller-visible summary for that domain; the unknown
implementation is not attributed or traced. Without such a contract,
`unresolved-call-target` controls the remaining coverage gap. Unresolved
function-pointer calls have no declaration fallback and remain coverage gaps.
Sniff-test does not guess either kind of target by joining unrelated call sites
that happen to share an erased type.

`ambiguous-effect-marker`, `ambiguous-effect-requirement`, and
`analysis-incomplete` set group defaults for both effect domains. An explicit
panic- or safety-specific key takes precedence over its group default
regardless of TOML ordering. `warn` accepts the ambiguity but reports it;
`allow` accepts it silently.

`panic-analysis-incomplete` controls incomplete panic traversals, and
`safety-analysis-incomplete` controls incomplete safety traversals. These
findings distinguish paths truncated by `max-trace-depth`, effect traces that
exhaust `trace-state-budget`, and reachable managed bodies that are absent from
the linked artifact graph.

Exact `compiler-assert-*` keys override `compiler-assert` for their assertion
subtypes. Exact non-call unsafe-operation keys override
`unsafe-op-missing-justification` for their operation subtypes. Compiler-assert
findings use `kind = "compiler-assert"` with `compiler-assert-kind`; unsafe
operations use `kind = "unsafe-op-missing-justification"` with
`safety-op-kind`.

`marker-probing = "macro-definition-first"` lets `// PANIC:` and `// SAFETY:`
markers inside macro definitions satisfy operations produced by that macro,
then falls back through macro callsites to the outer source callsite.
`source-callsite` keeps lookup at the final user callsite only.

`effect-doc-matching = "any-justification"` (the default) lets any nonempty
`// PANIC:` or `// SAFETY:` explanation discharge the corresponding complete
effect contract, regardless of its requirement-list layout. Set it to `"exact"`
to require each documented sub-obligation to be justified by name, or by the
same nested list structure when it has no explicit name.

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

Use `[panics].trusted-boundary-namespaces` for APIs whose caller-visible panic
contract is authoritative. This is a panic-domain analysis boundary, not a
diagnostic severity override. PanicEffect sources owned by a matching
implementation do not propagate out of it. Panic-domain CommentEffect
contracts reached by calls made inside that implementation do not leak out
either, even when the internal helper belongs to another namespace. The
matched API's own `# Panics` contract remains its public surface: it propagates
to a non-trusted caller and must be justified there. A matching API without a
`# Panics` contract is trusted as having no caller-visible panic behavior. A
broad glob therefore asserts that the matched library documents every
caller-visible panic condition. The manifest generated by `cargo sniff-test
init` explicitly trusts `core`, `alloc`, and `std`; remove an entry—or use `[]`—to
audit those implementation internals.

`[panics].ignored-namespaces` matches both definition namespaces and macro
definition paths in panic-source, invocation, and documented-contract
provenance. The default contains
Rust's `core::ub_checks::assert_unsafe_precondition`, whose generated panics
diagnose violated unsafe preconditions rather than caller-visible panic
behavior. A macro match terminates only that panic path, including `# Panics`
contracts of helpers called by the expansion: unrelated panics in the same
function remain reportable, and safety analysis still audits the underlying
unsafe operation and its justification. An explicit list
replaces the default; use `ignored-namespaces = []` to trace these checks as
ordinary panic behavior.

`[safety].ignored-namespaces` likewise matches both definition namespaces and
macro definition paths in unsafe-source, invocation, and documented-contract
provenance. A macro match terminates only that safety path, including `# Safety`
contracts of helpers called by the expansion. Unrelated safety behavior in the
same function remains reportable, and panic analysis is unaffected.

Use `[safety].trusted-boundary-namespaces` for APIs whose caller-visible safety
contract is authoritative. SafetyEffect operations owned by a matching
implementation do not propagate out of it, and safety-domain CommentEffect
contracts reached by its internal calls do not leak out. The matched API's own
`# Safety` contract still propagates to a non-trusted caller, where its
requirements must be satisfied by a nearby `// SAFETY:` marker. Trusting the
callee does not suppress an unsafe invocation written in local code: that
SafetyEffect source belongs to the local caller and still needs a
`// SAFETY:` justification. An exported unsafe function selected as a report
root is likewise still checked for missing `# Safety` documentation. The
generated manifest explicitly trusts `core`, `alloc`, and `std`; remove an entry to
audit that crate's implementation internals.

Standard-library crates have distinct definition namespaces. The generated
policy includes all three to trust their public `# Safety` surfaces without
auditing implementation-internal operations, contracts, or marker ambiguity:

```toml
[safety]
trusted-boundary-namespaces = ["core", "alloc", "std"]
```

`std` does not implicitly include `core` or `alloc`; crate-root candidates
already cover every definition in the named crate, so `core::**` is not also
required. The same namespace rules apply to panic boundaries.

`[panics.lints].unresolved-call-target` and
`[safety.lints].unresolved-call-target` control calls whose remaining concrete
targets cannot be resolved. Both default to `allow`; known targets still
participate in effect tracing, and calls that are actually unsafe remain
SafetyEffect sources. Structured reports distinguish
`unresolved-panic-call-target` from `unresolved-safety-call-target`.

Use `[contracts].override-files` while auditing generated or third-party APIs
whose documented behavior is known but not written in source yet. This section
only configures where contract evidence comes from; it does not make a
namespace trusted or opaque. Domain boundaries remain under `[panics]` and
`[safety]`. Override files are TOML files keyed by Rust namespace globs; the
value replaces that function's rustdoc markdown for both panic and safety
contract parsing. The markdown is parsed as CommonMark, so normal headings,
setext headings, inline code, and formatted list text work as expected.

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
dependency units cache facts silently. Each workspace unit emits at most one
message with `"reason":"sniff-test-artifact"`. Reports have no dependency
`scope`, cache identity, or dependency list because every public report is a
workspace report. Reports use format version 17. A finding includes
`root-span` alongside `root` when the selected function's source location is
available and verified; `span` is the finding's effect location, and every
`trace` entry is a call or effect edge. Source findings also include an `owner`
with a conservative `workspace`, `dependency`, `toolchain`, or `unknown` scope,
plus `source-evidence` that distinguishes `present`, `verified-absent`, and
`unverified` marker evidence at the exact effect-source site. Markers encountered
later in a trace are represented by the effect's remaining requirements; they
do not change the source site's evidence status. Human diagnostics keep the
effect source as the primary location; for external sources, a reachable
workspace call may be shown separately as a place to contain that path. A
matched API's surface contract uses an ordinary domain finding kind such as
`documented-panic`, `unsafe-call-*`, or `safety-obligation-*`; the boundary does
not create a separate finding class.
sniff-test records an invocation token only in workspace dep-info, so Cargo
reruns report-producing workspace units on every invocation to reinterpret and
validate cached facts while leaving otherwise-fresh dependency units untouched.

Recorded dependency source ranges become rustc spans only after the source
file's stable identity, exact content hash, normalized byte length, and byte
range are verified. A source range that cannot be verified remains reportable
without a span. Marker-bearing source files receive an additional check before
interpretation: if the recorded path exists but its contents do not match, the
run fails rather than interpreting stale `// PANIC:` or `// SAFETY:` facts.

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

In exact matching mode, requirement lists accept unordered (`-`, `*`, `+`) and
ordered (`1.`, `1)`) Markdown items at any nesting depth. A `name: condition`
item is matched by name; an item without a name is matched by its structural
list path, so its call-site justification must reproduce the same nesting.
Rustdoc conditions may be empty when the name is enough, but call-site
satisfaction bullets must include justification text. Names are matched
case-insensitively, with punctuation and whitespace treated as separators, so
`bounded[total]` and `bounded total` match. Duplicate names inside one
documentation section are ambiguous under the effect-specific
`ambiguous-panic-requirement = "deny"` or
`ambiguous-safety-requirement = "deny"` policy: a single marker bullet cannot
prove two distinct requirements with the same normalized name. Prose and labels
such as `Requirements:` are allowed before the first bullet. Plain comment lines
following a requirement bullet in the same contiguous block are kept as
explanation context. Use `/// # Panics` to document public API panic behavior;
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

- `-e EFFECT`, `--effect EFFECT`: track only `panic` or `safety`; repeat to select both
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
that upstream rustc unit so it persists complete facts without diagnostics or a
JSON report.

Direct driver mode follows rustc-driver exit semantics: it returns success when
rustc succeeds, even if sniff-test emits findings. Required fact extraction or
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

The standalone `reachability` crate is an independent implementation whose
methodology was informed by
[Ferrocene](https://github.com/ferrocene/ferrocene), a downstream of the Rust
compiler maintained by Ferrous Systems. See
[ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md) for details.
