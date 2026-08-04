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

The frontend asks driver-built dependencies to encode MIR. This lets a
consuming unit record an exact-instantiation overlay when generic dispatch is
selected using a consumer-local type; for example, a dependency generic that
calls a trait implemented by a workspace type. The dependency's own v13 cache
still supplies its defining, generic body and raw THIR-only facts.

External code without encoded MIR remains opaque to that rustc unit. Ordinary
dependency coverage comes from v13 artifact IR produced during each
dependency's compilation and composed by stable function identity. Sysroot
crates are not driver-compiled and therefore have no defining artifact cache;
an exact sysroot instantiation is traversable only when rustc exposes its MIR
to the consumer. Other `std`/`core`/`alloc` crossings remain raw boundaries
whose treatment depends on configured panic sinks, contracts, trusted
boundaries, and opaque-boundary policy. Broad trusted globs assume complete
documentation and can hide undocumented effects.

### The node limit bounds workspace interpretation

Each selected workspace-root traversal visits at most `[analysis] node-limit`
functions (default 4096). Dependency extraction is root-independent and is not
truncated according to workspace reporting policy. Halting during
interpretation is loud through the effect-specific analysis-incomplete lint,
which denies by default, but the region beyond the halt is simply unknown.

### Missing managed dependency bodies are reported separately

Failure to produce, validate, or persist required artifact IR is a tool error.
If a reached body from a managed dependency is nevertheless absent from the
composed graph, interpretation emits an incomplete-analysis finding. The
optional `dependency-panic-analysis-incomplete` and
`dependency-safety-analysis-incomplete` overrides can change the policy for
that missing cross-crate body without weakening the workspace node-limit
finding above.

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

### Artifact IR validity rides on rustc identity and v13 fingerprints

Dependency IR is reused only after the v13 envelope validates its tool and
rustc versions, artifact-local compiler fingerprint, canonical content ID,
exact dependency-generation references, stable function identities, and source
content hashes. A direct cache is additionally matched against the actual
rustc-loaded crate name, stable crate ID, and strict version hash (SVH), so a
stale sidecar beside a replaced fixed-name rlib is rejected. Transitive caches
are pinned by the exact analysis generation recorded by their parent.

The workspace's compiler profile is not compared with dependency fingerprints:
Cargo package-profile overrides may compile them differently. The dependency's
own compiler settings contribute to its rustc identity and cache generation.
Lint levels, report roots, and other interpretation-only policy deliberately do
not invalidate dependency IR; the workspace reinterprets the same facts under
the active configuration. Sharing a cache with a modified toolchain that
misreports the same version and produces colliding rustc identities remains
outside this validation model.

### Cached source spans require the original source

Dependency IR stores stable source-file identity, filename, exact content hash,
normalized byte length, and file-relative byte ranges. A workspace loads the
recorded file into rustc's active source map and uses its span only when every
value matches. Missing, edited, remapped-to-a-different-identity, or malformed
source degrades to an unspanned diagnostic. This preserves diagnostic honesty
but loses the source snippet and precise location.
