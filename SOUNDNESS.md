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
its own (the docs live on `Index::index`), so a trusted boundary treats it as
non-panicking instead of inheriting the trait method's named requirements. A
trait-method-docs fallback belongs with the consistency check above.

### Safety precondition asserts are not panic evidence

Compiler checks for null pointer dereference, misaligned pointer dereference,
and invalid enum construction inside an unsafe function with `# Safety` docs
are treated as safety-requirement evidence, not as `# Panics` evidence. The call
site must justify the safety requirements through `// SAFETY:` markers; once that
obligation is handled, panic analysis should not also require callers to
document the callee's internal UB guard as a panic. Other compiler assertions
inside the same unsafe function — bounds checks, overflow, division by zero,
and explicit panic sinks — remain panic evidence.

### Trusted boundary documentation is assumed complete

`trusted-panic-boundary-namespaces` and
`trusted-safety-boundary-namespaces` stop traversal at matching APIs. Their
documented requirements become caller obligations, but undocumented matches
are trusted as having no corresponding effect. An incomplete external contract
therefore hides real behavior—including the generic obligation normally
reported for an undocumented `unsafe fn`. Use narrow audited patterns and
documentation override files when source documentation is missing.

### Build scripts and proc macros are dependency-scoped

Units whose crate name is Cargo's `build_script_build` or whose crate type is
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
deep as encoded MIR allows. Audited APIs can be configured as trusted
boundaries, but broad globs trust their documentation completeness and can hide
undocumented effects.

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
precise value-flow analysis and can over-report. A concrete target therefore
does not discharge the generic effect of an erased callable: another function
pointer value or dyn object of the same erased type may still reach that call
site.

### Marker suppression is source-anchored

`// PANIC:`/`// SAFETY:` markers attach to source spans: the callee segment's
line, the statement line for single-line statements, and for panic markers the
nearest enclosing block when no call-local marker exists. Unusual formatting —
a call split across lines in ways rustfmt does not produce — can anchor a marker
to a different link than the author intended. Named requirement bullets are
matched by normalized name and are format-insensitive, but duplicate names in
one documentation section are ambiguous under the default
`ambiguous-effect-requirement = "deny"` policy.

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

### Dependency cache validity rides on cargo fingerprints

Dependency caches are trusted for fresh units on the strength of the injected
fingerprint inputs (`sniff_test_config_*`, `sniff_test_tool_*` cfgs,
`SNIFF_TEST_ARGS` env-depinfo, rustc-scoped target directories). Anything that
bypasses cargo's fingerprinting — hand-editing files under `target/`, sharing a
`--cache-dir` across machines with differently-patched toolchains of the same
version string — can replay stale effect evidence.
