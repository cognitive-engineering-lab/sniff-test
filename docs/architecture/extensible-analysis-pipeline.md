# Extensible analysis pipeline

## Status

Accepted for incremental implementation on `refactor/sniff-test`.

## Context

`sniff-test` currently extracts policy-neutral compiler data, persists it per
rustc artifact, composes local and dependency artifacts, and interprets only
data reachable from selected workspace roots. Those are the right lifecycle
boundaries. The limitation is inside each boundary: functions own fixed lists
of calls, panic/safety effects, and markers, and interpretation produces fixed
trace and finding enums. Adding an unrelated analysis would therefore require
editing central panic/safety types.

The replacement keeps the current lifecycle while making its semantic content
open-ended:

```text
rustc inputs            human-authored inputs
      |                           |
      +---- artifact pass DAG ----+
                    |
          typed artifact database
                    |
       exact-artifact composition
                    |
          root evaluation-rule DAG
                    |
       typed obligations and issues
                    |
       registered issue renderers
```

The extension boundary is compile-time registration. There is no dynamic
plugin ABI, unsafe typemap, global compiler-event enum, or untyped API for
normal analysis code.

## Schema identity and registration

Every row schema owns a stable string ID and an independent integer version.
IDs describe semantics rather than Rust module paths, for example
`sniff-test.core.function` or `sniff-test.panic.mir-assert`. Renaming a Rust
type does not change its schema ID. A semantic or encoded-shape change bumps
that table's version; unrelated tables keep their versions.

Schemas implement typed marker traits:

```rust
trait RowSchema: Serialize + DeserializeOwned + Clone + 'static {
    const ID: &'static str;
    const VERSION: u32;
}

trait EntitySchema: RowSchema {
    type Key: Ord + Clone + Serialize + DeserializeOwned;
    fn key(&self) -> Self::Key;
}

trait FactSchema: RowSchema {}

trait RelationSchema: RowSchema {
    type From: EntitySchema;
    type To: EntitySchema;
}
```

Requirements and issues use separate marker traits rather than variants of a
global enum. A schema-local enum, such as the MIR assertion subtype, remains
appropriate because extending another analysis does not modify it.

The registry rejects duplicate schema IDs, a Rust type registered under two
IDs, incompatible versions, mismatched schema kinds, and relation schemas
whose endpoint schemas are not registered as entities. Descriptors contain
monomorphized serde and validation functions. Type erasure occurs inside those
infrastructure adapters only; pass, rule, and renderer implementations use
typed APIs.

## Typed and erased references

Collection uses symbolic typed handles:

```rust
struct EntityHandle<E: EntitySchema> {
    key: E::Key,
    marker: PhantomData<fn() -> E>,
}
```

They can be created before canonical row numbers are known and can cross pass
boundaries through immutable draft views. A pass refers to an existing entity
by its typed stable key, never by an insertion index.

Finalized typed views expose `EntityId<E>`. Infrastructure that must mix
schemas uses `EntityRef { schema, row }` and `RowRef { schema, row }`.
Normal analysis code neither constructs erased references manually nor
downcasts rows.

References inside one persisted database are artifact-local. Composition adds
an exact generation scope:

```text
ArtifactScopeId = canonical persisted rustc identity or numbered in-memory generation
ScopedEntityRef = (ArtifactScopeId, EntityRef)
ScopedRowRef = (ArtifactScopeId, RowRef)
```

Rows from two consumer artifacts are never flattened into one ID space.
Stable entity keys may discover join candidates, but they never create a
provenance edge. Explicit typed composition relations select definitions,
exact instances, and callable targets, while the enclosing generation remains
part of every endpoint and row reference. This preserves
consumer-instantiation isolation.

## Persisted artifact database

The open container has no domain-specific fields:

```text
ArtifactFactIr
  format-version
  tables[]
    schema
    version
    kind
    rows[]
      stable-key?   # entity rows only
      data
  fact-index[]
    fact row, owner?, anchor?, provenance root?, producer, requirements[]
  relation-index[]
    relation row, from, to, source anchor?
```

`data` and stable keys are JSON values at the persistence boundary. Registered
typed views deserialize them through the schema descriptor. Unknown tables
remain byte-semantically representable and participate in generic validation
and relation adjacency; typed consumers simply cannot query their rows. A
known schema with the wrong version is an error rather than an unknown table.

Each encoded table declares its infrastructure kind. Persisted artifact
databases permit `entity`, `fact`, `relation`, and `requirement` tables. The
ephemeral evaluation database additionally stores independently registered
`derived` rows and `issue` rows. These are not semantic-domain variants; the
kinds let the core enforce which stage owns a row and validate opaque tables
without knowing what the rows mean. An artifact containing a derived or issue
table is invalid.

The container validates:

- unique table IDs and nonzero versions;
- canonical table and row order;
- registered schema kind and version compatibility;
- exactly one stable key on entity rows and none on other row kinds;
- unique stable entity keys within a table;
- unique canonical requirement rows within a table;
- fact metadata references to existing rows/entities;
- relation rows and endpoints that exist and have the declared kinds;
- canonical relation and fact indexes.

Unknown table contents are not semantically validated. Generic shape
validation first enforces explicit limits on table count; rows per table and
in total; combined fact/relation index rows; requirement references per fact
and in total; bytes per string; JSON depth and nodes per value; and JSON bytes
per erased value and across all erased row values. These checks apply after
deserialization. A v17 cache reader must independently bound the raw cache file
before parsing and may supply tighter limits.

## Deterministic finalization

Pass commits merge symbolic deltas into a draft database. Numeric row IDs are
assigned only once, after every artifact pass has succeeded:

1. Canonicalize JSON objects recursively by key.
2. Sort tables by schema ID.
3. Sort entity rows by canonical serialized stable key; reject duplicates.
4. Assign entity row IDs and build the symbolic-key-to-row map.
5. Sort requirement rows by canonical row bytes, assign their row IDs, and
   resolve symbolic requirement handles.
6. Resolve fact owners, anchors, provenance roots, requirement references,
   and relation endpoints.
7. Sort facts by schema, resolved metadata, then canonical row bytes.
8. Sort relations by schema, endpoints, source anchor, then canonical row
   bytes, and assign relation row IDs.
9. Sort the generic indexes by their full serialized keys.

Temporary allocation order, hash-map iteration, pass execution order, and pack
registration order are never tie-breakers. Exact duplicate entity identities
are rejected. Exact duplicate facts and relations are retained only when their
schema defines occurrence identity in the row; otherwise producers must give
them distinct stable entities or avoid emitting the duplicate.

Serialization tests compare complete encoded bytes after reversed insertion
and registration order.

## Artifact pass DAG

An artifact pass declares a stable pass ID, required input schemas, and output
schemas. It receives an immutable view of all successfully committed earlier
passes and an isolated output delta. The scheduler:

- resolves producers from declared writes;
- rejects duplicate pass IDs and ambiguous producers;
- rejects a missing required producer;
- topologically orders passes;
- chooses lexicographic `PassId` order among independent ready passes;
- rejects dependency cycles with the involved pass and schema IDs;
- permits reads only from schemas declared by the active pass;
- rejects writes not declared by the active pass;
- discards the complete delta when a pass fails;
- materializes declared empty output tables so downstream inputs are present;
- commits only after the pass returns success and the merged database
  finalizes and validates.

Compiler access is exposed through a typed `PassCx` with cached reachability,
MIR, THIR, source-map, type, and body helpers. Source-specific shared walkers
may fan out to probes, but they are optimizations behind passes rather than the
semantic extension API.

Producers must be registered explicitly. A pack cannot access a schema merely
because the Rust type is visible, and an artifact pass cannot read or write an
evaluation-only derived or issue schema.

## Analysis packs

An analysis pack registers schemas, artifact passes, evaluation rules,
relation presenters, issue renderers, and any configuration adapter it owns.
Registration is ordinary Rust code in the composition root:

```text
CoreProgramPack
HumanContractsPack
PanicPack
SafetyPack
```

Installing a future allocator pack adds that pack and its composition-root
line. It does not edit the artifact container or any global event, effect,
trace, requirement, or finding enum.

A test-only sample pack is the architectural proof. It defines an unrelated
entity, fact, relation, requirement, issue, presenter, and renderer; runs its
artifact pass and evaluation rule; finds its relation through generic
adjacency; and renders the issue without changing core types.

## Provenance relations and traces

Artifact-local relations are persisted typed rows with separate generic
endpoints and source anchors. Root-specific cross-artifact resolution emits
typed composition relations into an ephemeral, root-branded relation store;
these rows never enter an artifact cache. Core program relations initially
include ownership, calls, macro expansion, exact-instance selection, callable
erasure/invocation, and consumer overlay provenance. Panic and safety packs add
their own relations without changing core.

The composed database builds deterministic outgoing and incoming adjacency
from every relation-index row, including unknown relation schemas. Root
evaluation records relation references while traversing. An issue trace is a
selected path of `WorkspaceRelationRef`s, whose fixed infrastructure variants
refer to either a scoped persisted row or a root-scoped composition row. It is
not pre-rendered text and not a semantic step enum; adding a relation schema
does not change the reference type.

Each known relation schema may register a presenter. Persisted and composition
relations have separate validated presentation contexts because only the
latter may cross scopes. Rendering walks selected relation references and
dispatches through their schema-owned presenters. Unknown persisted relations
remain traversable and receive a schema-ID fallback description. Path selection
uses a deterministic shortest-path order based on scoped source entity,
relation schema ID, relation row, and destination entity.

## Compiler and human provenance

Compiler facts and human-authored declarations are separate schemas.

- Compiler facts describe MIR assertions, unsafe operations, calls, instance
  selection, callable erasure, and other compiler evidence.
- Contract declarations own human requirement rows.
- Evidence claims retain their exact source anchor, domain, optional named or
  explicit requirement references, and rationale.
- Attachment candidates retain macro-definition and expansion-callsite
  provenance while rustc hygiene is available.
- A linking pass emits resolved evidence-attachment relations or explicit
  unbound/ambiguous attachment facts.

Configuration selects which already-extracted attachment relation is active;
it does not cause dependency extraction to discard alternatives. Empty human
rationales never satisfy requirements.

## Workspace evaluation

Artifact composition retains exact generation scopes and source identities.
Workspace evaluation is a separate rule DAG, run for each selected root and
effect domain. Rules consume typed artifact facts/relations and produce typed
requirements, obligations, evidence matches, completeness outcomes, and
issues in an ephemeral evaluation database.

Obligations, evidence matches, and completeness outcomes are ordinary
`DerivedSchema` rows. Rules declare their typed derived and issue inputs and
outputs; downstream rules can consume committed rows from earlier rules.
Multiple rules may produce the same derived schema, and a consumer runs after
all of those producers in stable pass-ID order. A failed rule contributes no
partial rows. Before evaluation begins, every declared artifact input table
must be present; an absent table is incomplete input, while a present empty
table is a valid zero-row result from its artifact producer.

An obligation refers to arbitrary requirement rows and to a trace target. It
does not contain a requirement enum. Evidence matching records the exact
requirement row references discharged by each claim. Panic call-site grouping
and safety unsafe-scope grouping are evaluation data, not renderer behavior.

The obligation source row, endpoint, complete scoped relation trace, and
deterministic traversal order form a reached witness's identity.
`ReachableMirAssert`, `ObligationRecord`, `EvidenceAttachment`, and
`PanicEvidenceMatch` carry that identity, and evidence matching keys on all
four components. Evidence attached to one route therefore cannot discharge an
otherwise identical visit with different propagated marker state. Evaluation
rejects duplicate reached identities and validates attachment row references,
endpoints, requirements, and paths before matching.

Contract boundaries expose their declared requirements to callers and stop
ordinary propagation of internal compiler effects. Whether a contract is an
accurate summary of its implementation is a separate future validation rule.

Missing managed bodies, graph/load failures, and node limits remain explicit:

- graph/load and artifact-validation failures abort before evaluation;
- a reached missing managed body emits the corresponding typed incomplete
  issue;
- every root/domain traversal carries its own node budget and completeness;
- unmanaged compiler boundaries retain their documented current behavior
  until a separate completeness-policy change is intentionally made.

Callable erasure and invocation relations are joined inside one root's
evaluation context. Raw artifacts never persist a root-specific inferred
target.

## Issues, policy, and rendering

Issue schemas are typed rows. Renderers are registered per issue schema and
are invoked through an erased infrastructure adapter that first decodes the
registered concrete issue type. Renderers may:

- resolve already-recorded source anchors through the verified source layer;
- select lint levels through the issue schema's policy adapter;
- format messages, requirements, and relation-presented traces;
- emit rustc diagnostics and public JSON.

Renderers do not create obligations, match evidence, probe compiler data, or
change reachability. Public report ordering is a generic stable key composed
from root, domain, trace relation references, anchors, schema ID, and
schema-specific issue ordering data.

## Source integrity

The core program pack retains the current stable file identity, filename,
content hash, normalized length, and file-relative ranges. Source anchors
reference those rows. Cached anchors become rustc spans only through the
existing verification boundary. Marker-bearing source verification remains a
pre-evaluation integrity check: dependency caches validate every permanent
marker-to-anchor-to-file chain against the active source map before it can
affect a finding. Macro
relations retain definition and source-callsite anchors so either probing
policy remains expressible.

## Migration sequence

This sequence describes the authority boundary expected after each step is
complete. It is not a claim that an in-progress vertical slice already owns
production diagnostics; the implementation-state section below records the
current cutover boundary.

1. **Infrastructure:** add the registry, typed/symbolic IDs, open artifact
   database, canonical builder, typed views, relation adjacency, pass DAG, pack
   registration, renderer adapters, the test-only extension pack, and the
   strict cache envelope for permanent typed artifact data.
2. **MIR assertion slice:** collect function/effect/source entities, call and
   assertion provenance relations, typed MIR assertion and compiler
   requirement facts, and panic evidence claims. Evaluate them per root into a
   typed unsatisfied-obligation issue and render the existing human/JSON
   result. This becomes authoritative for compiler assertions.
3. **Safety and human facts:** migrate THIR operations, unsafe groups,
   `BuiltinUnsafe`, contracts, evidence attachment, ambiguity issues, and
   safety completeness to permanent packs.
4. **Composition and callable joins:** move scoped body resolution,
   source/runtime contract fallback, exact/generic lookup, and callable joins
   onto composed fact databases.
5. **Removal:** after both domains migrate, remove legacy IR from the cache and
   production interpretation, retain it only as an in-memory test parity
   oracle, then remove the remaining legacy effect/marker/finding/trace enums
   and pending extraction structures.

The facts-only cache is format 17 in directory `v17`. Both panic and safety
findings now use permanent representations and unified per-domain evaluation
paths; missing selected roots use ordered preparation bridges because they have
no evaluation root. Legacy IR is neither serialized nor read by production and
exists only in test builds as an in-memory parity oracle. Report format 14 adds
trusted-safety provenance and the distinct indirect-safety-boundary finding.

## Implementation state

The schema registry, symbolic builder, encoded container, validated typed
views, non-flattening workspace composition, persisted and composition
relation graphs, artifact-pass scheduler, evaluation-rule scheduler, pack
registration, renderer registries, and test-only extension pack exist under
`analysis::facts`. The sample pack exercises collection, serialization, typed
reopening, same- and cross-artifact path selection, root-specific evaluation,
and rendering through those interfaces.

The core program pack defines function keys containing the stable definition
and optional exact-instance identity; function rows retain defining- or
consumer-instantiation provenance. Effect-site keys contain that function key
plus the exact MIR block and statement coordinates. Typed relations connect
anchors to verified files, functions to declaration anchors and effect sites,
effects to presentation and expanded anchors, functions through ordered macro
expansion chains, expansions to effects, and expansions to callsite anchors.
The typed core topology also represents callable declarations and keys, exact
call sites and occurrences, runtime and source-contract targets, attribution
modes, safety-effect groups, source-anchor roles, and occurrence-specific macro
paths. Every real call, MIR-effect, and unsafe-operation macro frame carries
rustc's stable expansion hash in addition to its definition and presentation
data. This distinguishes repeated expansions even when copied tokens produce
the same source callsite; no typed identity is reconstructed from a span or a
session-local expansion number.

`CollectedArtifact` is the owned, policy-neutral compiler handoff for the new
artifact passes. It validates the complete core topology together with panic
and safety contracts, unsafe operations, compiler assertions, and permanent
human marker rows before any pass can mutate a builder. The combined
`CollectedArtifactPack` installs one producer for core program rows, panic
contracts, compiler assertions, safety rows, and human markers. Each pass
declares its exact reads and writes, materializes empty tables, and produces
canonical output independent of collection order. Production rustc extraction
constructs this validated handoff directly from compiler state and runs the
combined permanent pack as the only persisted artifact representation. The
typed artifact is therefore a primary collection result, not a reconstruction
from legacy rows.

`WorkspaceProgramIndex` is the one-time, exact-generation preparation boundary
for those permanent program facts. Its caller supplies the verified stable
crate identity for every workspace scope; preparation rejects missing or extra
owners and checks defining/consumer provenance against that trusted envelope
metadata. The index validates source ownership, function/callable identity,
function-to-site-to-occurrence adjacency, call targets and safety groups,
call/effect/unsafe macro paths, permanent marker claims and candidates, and
duplicate semantic relations before traversal. Queries use exact scope plus
semantic keys rather than accepting replayable row references. Callable
evidence is indexed once across the workspace and can only be queried through
a branded, caller-supplied reachable-scope view. The index exposes candidates;
it does not choose a defining artifact, attribution mode, or traversal policy.
It also retains the exact persisted relation references for call and MIR-effect
ownership, source roles, targets, marker candidates, and every macro entry,
link, callsite, and exit. A traversal can therefore preserve the compiler's
selected route without reconstructing it from hashes or asking the mixed graph
for a shortest path.

A policy-neutral, root-scoped program traversal now consumes this index. Its
authority map is explicit and contextual by preferred artifact generation and
stable crate identity; absence is an error rather than an implicit unmanaged
boundary. The iterative engine selects exact then same-scope generic bodies,
keeps consumer-instantiation bodies as the runtime route, records an explicitly
managed defining body only as a source side edge, and retains generation-aware
unmanaged and missing-body outcomes. It uses exact indexed artifact relations,
a parent-linked path arena, marker-state visit keys, deterministic cycle and
deduplication outcomes, and a node budget charged only when a new body is
expanded. Prepared composition rows are emitted transactionally, finalized
once, recovered by full typed identity, and validated as exact paths; a later
row failure cannot leak a partial traversal into the caller's builder.

Every expanded body records its exact owned effects in canonical MIR-site order
before its calls. Effect visits own their scoped entities, source roles,
depth-aligned macro metadata, exact root-to-effect traces, and distinct
inherited, attached, and active permanent marker claims. Call candidates are
filtered by exact domain and probing mode and transported only when the call is
followed. Visit identity contains only transported claims.

Reached callable evidence and callable-key invocations form a traversal-local
fixpoint. Only reached evidence can resolve an invocation, both arrival orders
are supported, duplicate targets retain one canonical provenance, and every
synthetic resolution owns both its invocation-to-callable edge and an
independently validated evidence trace. Consumer/defining calls reconcile by
exact anchors, effective definition or complete role-sensitive target shape,
with actual-call source fallback. The complete candidate set is exposed to the
domain policy for one all-or-none marker decision. Followed calls, boundaries,
effects, bodies, source selections, and reconciliation edges are retained as
resolved semantic records; no path is recovered with a shortest-path query.

`WorkspaceMirAssertIndex` binds permanent assertion rows to exact effect sites
and rejects missing producer tables, malformed owners, duplicates, and invalid
requirements before evaluation. Effective panic and safety contract indexes
snapshot runtime documentation overrides, prefer exact then same-scope generic
owners, never cross generations, and reject replacement workspaces.

Permanent marker occurrences own verified anchors, expansion paths,
source-ordered domain claims, and typed candidate relations to functions,
calls, effects, and unsafe operations. `MarkerClaimEntity` is the sole
compiler-assert claim authority. `EvidenceAttachment` and the panic matching
rules carry that exact scoped entity identity, separate semantic endpoint and
group identities, exact traces, and dense traversal order. The old
`EvidenceClaim` schema and all legacy bridge, trace, evidence, linker, and
temporary binding tables have been removed.

Domain matchers retain `EvidenceUseRecord` v4 unchanged: each row names the
exact claim, semantic group, source, endpoint, trace, witness order, and
presentation-stable semantic order for one use. The shared coordinator decodes
that claim and resolves its exact `MarkerOccurrenceEntity` by typed key in the
same artifact scope. It groups uses by root domain plus scoped physical marker,
so separate source-ordered bullets in one marker block cannot independently
justify different semantic groups. `AmbiguousEvidenceReuseIssue` v3 records
the scoped marker, the selected canonical witness source, endpoint, and order,
and the union of distinct groups. Its issue context uses the marker row as the
diagnostic source and the canonical use for endpoint and trace. Foreign-root or
domain rows, mismatched claim domains, and orphan occurrences fail the whole
coordinator rule before any ambiguity issue is staged.

Production extraction returns one validated permanent fact database. In test
builds the same neutral pending model also yields legacy IR for parity checks;
that oracle is not part of the serialized bundle. Collection or finalization
failure rejects the whole extraction. The strict format-17 cache accepts only
permanent facts, and unknown historical adapter tables remain inert.

The production driver installs one `AnalysisRegistry<PanicRootInputs>` with the
compiler-assert, panic-call, root-contract, completeness, and shared evidence
packs. It verifies one exact managed workspace closure and classifies every
requested root through an ordered `TypedPanicRootPreparationReport`. Only ready
requests enter one shared `PreparedCompilerAssertRootBatch`. Each ready root is
emitted into one composition builder, finalized and bound once, then evaluated
in exactly one fresh `EvaluationDb`; all five panic report lanes are read from
that one result. There is no second compiler-only production registry or
evaluation database.

The five sparse ready-root lanes are compiler assertions, panic calls,
selected-root contract duplicates, panic completeness, and occurrence-wide
marker ambiguity. Every evaluatable preparation retains the exact core-created
`EvaluationRoot` and maps to a dense report index. A missing preparation carries
the legacy-compatible `MissingBody` reason without fabricating an
`EvaluationRoot`, issue, summary row, or ready report. If every request is
missing, one exact request still passes through the core preparer and only its
matching `UnknownRoot` is accepted, so global input and registry validation
cannot be skipped.

`UnsatisfiedCompilerAssertIssue` is the sole compiler-assert issue. Its
pack-owned renderer handles every precise `MirAssertKind`; the CLI adapts its
owned semantic trace and presentation to report-v14 without parsing renderer
JSON. The compiler-assert input rule validates the complete assertion and
marker-attachment set before committing any delta, and its trace projector
indexes each resolved root once rather than rescanning traversal state.

`PanicCompletenessPack` emits exactly one positive summary per ready root, even
when it has no incomplete reasons. Reached `MissingManagedBody` routes collapse
by their legacy scope-independent semantic identity while retaining the
earliest exact source and relation-trace witness; reached `BudgetExceeded`
frontiers collapse to one root-only reason. Missing selected roots stay outside
the pack because no evaluation root exists for them, and are restored only by
the ordered preparation bridge described above.

`PanicRootContractPack` consumes the retained
`PanicContractBoundary::Root` directly. A selected root contract is a body
boundary rather than a call obligation, so its exact selected-body endpoint and
empty root trace are not duplicated into a derived row. The rule emits one
strict-v1 issue per lexically ordered normalized duplicate group, preserving
declaration-order requirement ordinals. Projection reconstructs the exact raw
contract source (absent for overrides), endpoint, and trace and requires a
bijection before report adaptation. Policy precedence remains ignored root,
override, raw exact, raw generic, then trusted fallback; an override without
`# Panics` removes raw authority.

The unified report adapter validates the complete preparation mapping, every
lane's count/order/root identity, every cross-lane `EvaluationRoot`, every
fallible panic-call DTO projection, and all compiler-renderer compatibility
before the first source lookup. It then adapts compact or full traces through
the existing report-v14 boundary; unavailable source identities degrade in the
same way as legacy output. Any validation or adaptation error drops the local
batch, so partial typed findings cannot escape.

Production also installs one `AnalysisRegistry<SafetyRootInputs>` containing
root contracts, calls, unsafe operations, completeness, and shared evidence
coordination. Every ready safety root uses one composition and one evaluation
database, and its five sparse report lanes are source-free preflighted before
adaptation. Trusted safety boundaries preserve the precise missing-
justification or missing-requirements class while carrying explicit provenance;
opaque targets produce a distinct indirect safety boundary issue.

Legacy traversal entry points are compiled only for tests. Their shared data
types and neutral pending extractor remain temporarily available to build the
in-memory two-domain parity oracle, but no legacy IR is serialized, loaded,
traversed, or used for source resolution in production.

## Rejected alternatives

### A single extensible enum

Macros can generate a large enum, but every pack still edits one closed-world
type and all consumers still recompile exhaustive matches. This does not meet
the extension objective.

### `Any` or an unsafe typemap in analysis code

It moves compile-time failures to runtime and makes schema/version mistakes
easy. Serde-based erasure at registry and persistence boundaries is slower but
safe, reviewable, and sufficient for compile-time analysis.

### Runtime dynamic plugins

They require an ABI, toolchain compatibility rules, and stronger isolation.
The intended packs ship with the pinned compiler tool, so compile-time
registration is simpler and safer.

### Assigning row IDs as passes commit

Later rows could sort before earlier rows, making IDs depend on execution or
registration order. Symbolic stable-key handles and one final assignment avoid
that dependency.

### Flattening artifact databases during composition

It makes exact consumer overlays from unrelated rustc generations
indistinguishable. Scoped references preserve the current correctness
boundary and still allow joins by stable semantic keys.
