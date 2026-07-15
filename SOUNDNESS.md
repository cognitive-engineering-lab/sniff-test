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
`crates/sniff-test/src/panics.rs`). Nothing verifies that impls document at
most what their trait promises, so an impl that panics more than the trait
documents escapes through a documented-looking boundary. The original
implementation had this check (`check_consistent_w_trait_requirements`);
restoring it is deferred feature work.

### Trait-impl methods do not inherit trait-method docs

A resolved direct call to a trait-impl method consults the impl method's own
docs only. `<Vec<T> as Index<usize>>::index` carries no `# Panics` section of
its own (the docs live on `Index::index`), so a trusted-namespace boundary
classifies it as non-panic evidence instead of a documented obligation — see
the `std_trait_impl_glob` fixture's `get` root. A trait-method-docs fallback
belongs with the consistency check above.

### Dependency safety analysis is not performed

Safety (unsafe-justification) analysis runs only for workspace crates
(`analyze_crate` in `crates/sniff-test/src/cli/mod.rs`). Dependencies get
panic analysis and caching, but their unsafe blocks are never audited. The
original's `DependenciesPosture::Verify` offered this; restoring it is a
pending feature decision.

### Safety precondition asserts are not panic evidence

Compiler checks for null pointer dereference, misaligned pointer dereference,
and invalid enum construction inside an unsafe function with `# Safety` docs
are treated as safety-requirement evidence, not as `# Panics` evidence. The call
site must justify the safety requirements through `// SAFETY:` markers; once that
obligation is handled, panic analysis should not also require callers to
document the callee's internal UB guard as a panic. Other compiler assertions
inside the same unsafe function — bounds checks, overflow, division by zero,
and explicit panic sinks — remain panic evidence.

### Per-function TOML requirement overrides were dropped

The original could attach named requirements to external undocumented
functions from the manifest (`annotations/toml.rs`). The refactor's namespace
lists can force a generic justification (`safety-obligation-namespaces`) but
cannot express named per-function requirements.

### Build scripts and proc macros are dependency-scoped

Units whose crate name starts with `build_script_` or whose crate type is
`proc-macro` never receive workspace deny gating or diagnostics
(`CrateOutputScope::current`). Their code runs at build time on the developer
machine; panics there fail builds loudly on their own, and holding them to
target-code policy would deny the ordinary panic-on-error idiom. Their code is
still analyzed and cached as dependency evidence.

## Analysis limits

### MIR availability bounds external descent

Reachability descends into external functions only when their MIR is encoded
in the rmeta (generic, `#[inline]`, or cross-crate-inlinable functions).
Plain external functions are opaque; coverage comes from the dependency
cache (each dependency is analyzed during its own compilation) plus the
`indirect-call-boundary` lint for unresolvable targets. Sysroot crates are
never driver-compiled, so `std`/`core`/`alloc` internals are covered only as
deep as encoded MIR allows — the recommended trusted-namespace config treats
them as documented API boundaries instead.

### The node limit bounds every traversal

Each per-root query visits at most `[analysis] node-limit` instances
(default 4096). Halting is loud — the `analysis-incomplete` lint denies by
default, and truncated cached summaries are marked `analysis-complete: false`
and treated as raw panic evidence by consumers — but the region beyond the
halt is simply unknown.

### Callable call-site attribution is type-keyed

With `callable-edge-attribution = "call-sites"`, function pointers and dyn
dispatch are resolved conservatively from erased types reached in the same
query. If one reached closure or function item reifies to `fn() -> i32`, every
reached `fn() -> i32` call site may connect to that target; similarly, every dyn
call to a trait may connect to every reached concrete vtable entry for that
trait. This avoids false negatives from simple erasure flows, but it is not
precise value-flow analysis and can over-report.

### Marker suppression is source-anchored

`// PANIC:`/`// SAFETY:` markers attach to source spans: the callee segment's
line, the statement line for single-line statements, and for panic markers the
nearest enclosing block when no call-local marker exists. Unusual formatting —
a call split across lines in ways rustfmt does not produce — can anchor a marker
to a different link than the author intended. Named requirement bullets are
matched by normalized name and are format-insensitive, but duplicate names in
one documentation section are ambiguous under the default
`ambiguous-panic-requirement = "deny"` or
`ambiguous-safety-requirement = "deny"` policy.

## Latent hazards (not reachable through the shipped tool)

### First-reach gating in the reachability API

`crates/reachability/src/analysis.rs` enqueues a target only when the
*first* edge that reaches it wants descent. The shipped hooks decide descent
purely from the target, so every edge agrees; a third-party
`ReachabilityHooks` implementation whose `should_descend` depends on the edge
kind would silently under-traverse. Fix option: track descend-eligibility
separately from first-reach.

### Dyn-to-dyn upcasts are not traversed

`collect_dyn_trait_tails` in `crates/reachability/src/body.rs` handles
concrete-to-dyn unsizing; a `&dyn Sub` to `&dyn Super` upcast coercion
records no vtable entries of its own. Supertrait *method calls* through a dyn
object are handled (see the `supertrait_dyn_dispatch` fixture); the upcast
coercion itself is redundant with the original cast in practice, but a value
upcast in one function and called in another (in `call-sites` mode) can miss.

## Toolchain-pinned assumptions

### The unsafe-operation set mirrors rustc's checker

`crates/sniff-test/src/safety/thir.rs` ports rustc's
`check_unsafety.rs` arm for arm; the pinned toolchain in
`rust-toolchain.toml` is the source of truth. On toolchain bumps, diff the
port against rustc's file — a new `UnsafeOpKind` variant means a new
detection arm and a fixture. The `unsafe_ops` fixture covers the stable op
kinds; layout-constrained types, `unsafe_fields`, `unsafe_binders`, and
`#[target_feature]` calls are ported but have no fixture canaries yet
(nightly-feature crates).

### Rustflags composition masks config-file target flags

The frontend owns `CARGO_ENCODED_RUSTFLAGS`, folding in the user's env
rustflags and best-effort `build.rustflags` from config files. Config-file
`target.<triple>.rustflags` / `target.<cfg>.rustflags` entries are not
recovered and do not apply to the analysis build, which can make the analyzed
cfg set differ from the shipped build's.

### Outcome and cache validity ride on cargo fingerprints

Persisted unit outcomes and dependency caches are trusted for fresh units on
the strength of the injected fingerprint inputs (`sniff_test_config_*`,
`sniff_test_tool_*` cfgs, `SNIFF_TEST_ARGS` env-depinfo, rustc-scoped target
directories). Anything that bypasses cargo's fingerprinting — hand-editing
files under `target/`, sharing a `--cache-dir` across machines with
differently-patched toolchains of the same version string — can replay stale
verdicts.
