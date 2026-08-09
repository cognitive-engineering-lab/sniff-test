# Known soundness gaps

sniff-test aims to prove the absence of reachable panics and unjustified
unsafe operations. The gaps below are places where the analysis knowingly
under-approximates (can miss real problems) or leans on assumptions. Each
entry states the mechanism, when it bites, and its current status.

## Deliberate under-approximation

### Impl docs are not checked against trait docs

When a call resolves only to a trait method — a generic bound or dyn dispatch
— the trait method's `# Panics`/`# Safety` docs stand in for whichever impl
runs (`indirect-call-boundary` and the obligation flow in
`crates/sniff-test/src/analysis/interpret.rs`). Nothing verifies that impls
document at most what their trait promises, so an impl that panics more than
the trait documents escapes through a documented-looking boundary. sniff-test
does not compare impl contracts with their corresponding trait contracts.

### Trait-impl methods do not inherit trait-method docs

A resolved direct call to a trait-impl method consults the impl method's own
docs only. `<Vec<T> as Index<usize>>::index` carries no `# Panics` section of
its own (the docs live on `Index::index`), so a trusted boundary treats it as
non-panicking instead of inheriting the trait method's named requirements. No
trait-method documentation fallback is applied to a resolved impl method.

### Safety precondition asserts are not panic evidence

Inside an unsafe function with an effective `# Safety` contract, compiler
assertions for null-pointer dereference, misaligned-pointer dereference, and
invalid-enum construction are excluded from panic findings. The caller-facing
safety obligation comes from the function contract and is enforced at call
sites; the assertions themselves are not safety-operation findings. Every other
compiler assertion—including bounds, arithmetic, and coroutine-resume
checks—remains panic evidence, as do configured panic sinks.

### Trusted boundary documentation is assumed complete

`trusted-panic-boundary-namespaces` and
`trusted-safety-boundary-namespaces` make matching call targets opaque. Their
documented requirements become caller obligations; an undocumented matching
callee is trusted as having no corresponding effect. This does not suppress
`missing-safety-docs` on an exported unsafe function selected as a report root.
An incomplete external contract can therefore hide real behavior. Use narrow
audited patterns and documentation override files when source documentation is
missing.

### Build scripts are skipped and proc macros are dependency-scoped

Units whose crate name is Cargo's `build_script_build` are skipped. Proc-macro
units are treated like dependencies: they never select report roots, interpret
lint policy, emit diagnostics, or emit JSON reports, but they silently persist
policy-neutral artifact IR. Both kinds of code run at build time on the
developer machine; panics there fail builds loudly on their own, and holding
them to target-code reporting policy would deny the ordinary panic-on-error
idiom.

## Analysis limits

### MIR availability bounds external descent

The frontend enables MIR encoding for driver-built units. When rustc exposes
dependency MIR to a consuming unit, that unit can record an
exact-instantiation overlay for dispatch selected by consumer-local types. The
defining artifact cache supplies the generic body and source-level THIR facts.

`core`, `alloc`, and `std` are not driver-built, have no defining artifact
cache, and are not managed by the composed lookup. If one of their bodies is
unavailable, traversal stops without an incomplete-analysis finding. Contracts,
panic-sink, trusted-boundary, ignored-namespace, and unsafe-call signature
policies still apply at the entering edge. When rustc exposes MIR for an exact
sysroot instantiation, panic analysis can traverse its calls and compiler
assertions. Safety analysis cannot recover that definition's THIR
unsafe-operation or unsafe-scope facts; the overlay only relays calls back into
managed bodies. Broad trusted globs assume complete documentation and can hide
undocumented effects.

### The node limit bounds workspace interpretation

Each selected root is interpreted separately for panic and safety. Each
effect-domain traversal visits at most `[analysis] node-limit` distinct
function states (default 4096); a state includes the owning artifact and the
set of requirements already satisfied, so one function can consume more than
one slot. Dependency extraction is root-independent and has no workspace-policy
node limit. Reaching the limit emits the corresponding
`panic-analysis-incomplete` or `safety-analysis-incomplete` finding, denied by
default; the unvisited region remains unknown.

### Missing managed bodies are incomplete analysis

Failure to produce, validate, or persist required artifact IR is a tool error.
During interpretation, an absent reached body emits an incomplete finding only
when its stable crate ID is owned by the local IR or a loaded artifact.
`panic-analysis-incomplete` controls panic missing-body and node-limit findings;
`safety-analysis-incomplete` controls the corresponding safety findings.
Unmanaged compiler-crate bodies have the behavior described above.

### Callable call-site attribution is type-keyed

With `callable-edge-attribution = "call-sites"`, function pointers and dyn
dispatch are resolved conservatively from erased types reached in the same
query. If one reached closure or function item reifies to `fn() -> i32`, every
reached `fn() -> i32` call site may connect to that target; similarly, every dyn
call to a trait may connect to every reached concrete vtable entry for that
trait. This avoids false negatives from simple erasure flows, but it is not
precise value-flow analysis and can over-report. A concrete target therefore
does not discharge the generic effect of an erased callable: another function
pointer value or dyn object of the same erased type may still reach that call
site.

### Marker suppression is source-anchored

`// PANIC:` and `// SAFETY:` markers are matched against compiler spans according
to `marker-probing` under `[analysis]`. Its default,
`macro-definition-first`, checks the macro definition first, then expansion
call sites outward, then the final source call site. For an effect-bearing call,
a separately lined callee marker wins; otherwise the statement marker is used,
with the nearest enclosing block as fallback for both marker kinds. On a
multi-line call, an unnamed statement marker cannot select one link, although a
named requirement marker can. Unusual formatting can therefore attach a marker
to a different link than intended. Requirement names are normalized;
duplicates produce `ambiguous-panic-requirement` or
`ambiguous-safety-requirement`, both denied by default.

### Dyn-to-dyn upcasts are not traversed

Concrete-to-dyn unsizing records vtable entries, but dyn-to-dyn upcasting
records none. Supertrait method calls are handled when concrete vtable evidence
from the original unsizing is reachable in the same traversal. In `call-sites`
mode, an upcast value passed in from elsewhere can therefore reach a call
without corresponding concrete target evidence.

## Toolchain-pinned assumptions

### The unsafe-operation set mirrors rustc's checker

`crates/sniff-test/src/safety/thir.rs` ports rustc's
`check_unsafety.rs` arm for arm; the pinned toolchain in
`rust-toolchain.toml` is the source of truth. On toolchain bumps, diff the
port against rustc's file — a new `UnsafeOpKind` variant means a new
detection arm and a fixture. The `unsafe_ops` fixture covers the stable op
kinds, and `target_feature_call_safety` covers caller-relative
`#[target_feature]` calls, including a nested inline closure. Layout-constrained
types, `unsafe_fields`, and `unsafe_binders` are ported but have no fixture
canaries yet (nightly-feature crates).

The port is intentionally applied only to runtime function-like bodies.
Standalone const/static initializers and inline-const bodies are excluded from
sniff-test's runtime effect graph, even though rustc's checker also validates
their language-level unsafety.

### Rustflags composition masks config-file target flags

The frontend owns `CARGO_ENCODED_RUSTFLAGS`, folding in the user's env
rustflags and best-effort `build.rustflags` from config files. Config-file
`target.<triple>.rustflags` / `target.<cfg>.rustflags` entries are not
recovered and do not apply to the analysis build, which can make the analyzed
cfg set differ from the shipped build's.

### Artifact IR validity rides on rustc identity

Persisted artifact IR is addressed by rustc's stable crate ID plus strict
version hash (SVH). The cache envelope validates its tool and rustc versions,
exact artifact identity, stable function identities, dependency artifact
identities, and source-range structure. A behavior-changing replacement of a
fixed-name rlib has a different SVH and therefore selects a different cache
path; transitive edges likewise name the exact rustc artifact selected by their
parent. Multiple SVHs for the same stable crate ID may remain cached across
builds, but one composed rustc graph rejects that ambiguous combination.

Ordinary `// PANIC:` and `// SAFETY:` comments are deliberately outside rustc's
SVH even though they contribute marker facts to sniff-test IR. Before
interpretation, sniff-test verifies every marker-bearing source file whose
recorded path still exists against the content hash stored in its sidecar and
rejects a mismatch or reload failure. If that path is absent, the marker facts
remain trusted as part of the exact artifact sidecar. This relies on loadable
artifacts and their sidecars being produced together by the sniff-test driver;
replacing an artifact outside the driver while hiding its source is outside the
validation model.

The workspace's compiler profile is not compared with dependency fingerprints:
Cargo package-profile overrides may compile them differently. The dependency's
own compiler settings contribute to its rustc identity.
Lint levels, report roots, and other interpretation-only policy deliberately do
not invalidate persisted artifact IR; the workspace reinterprets the same facts
under the active configuration. Sharing a cache with a modified toolchain that
misreports the same version and produces colliding rustc identities remains
outside this validation model.

Local in-memory IR and loaded artifact IR are composed into one lookup and
interpreted together. Findings carry no cache provenance, and the active
configuration resolves severity from `FindingKind`; equivalent facts therefore
produce the same human diagnostics and JSON policy regardless of where their
body was loaded. Source availability can still determine whether a diagnostic
has a verified span, as described below.

### Cached source spans require the original source

Artifact IR stores stable source-file identity, filename, exact content hash,
normalized byte length, and file-relative byte ranges. A workspace loads the
recorded file into rustc's active source map and uses its span only when every
value matches. Apart from the pre-interpretation marker check above, missing,
edited, remapped-to-a-different-identity, or malformed source degrades to an
unspanned diagnostic. This preserves diagnostic honesty but loses the source
snippet and precise location.
