//! Pack-owned compiler-assert, requirement, evidence, and issue schemas.

use serde::{Deserialize, Serialize};

use super::super::evaluation::{RelationTrace, deserialize_strict_relation_trace};
use super::super::evidence::EvidenceSemanticOrder;
use super::super::schema::{DerivedSchema, FactSchema, IssueSchema, RequirementSchema, RowSchema};
use super::super::workspace::{ScopedEntityRef, ScopedRowRef};

/// Binary MIR operation whose compiler assertion protects against overflow.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum BinaryOverflowOperation {
    Addition,
    Subtraction,
    Multiplication,
    Division,
    Remainder,
    LeftShift,
    RightShift,
}

/// Arithmetic operation represented by a no-overflow requirement.
///
/// This enum belongs to the panic pack. Its shape prevents the impossible
/// `MirAssertKind::Overflow(Negation)` state while allowing binary and unary
/// assertions to share one typed requirement schema.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum OverflowOperation {
    Binary(BinaryOverflowOperation),
    Negation,
}

/// MIR assertion subtype local to the panic pack.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum MirAssertKind {
    BoundsCheck,
    Overflow(BinaryOverflowOperation),
    /// rustc reported an overflow check without a supported symbolic operation.
    OpaqueOverflow,
    OverflowNegation,
    DivisionByZero,
    RemainderByZero,
    ResumedAfterReturn,
    ResumedAfterPanic,
    ResumedAfterDrop,
    MisalignedPointerDereference,
    NullPointerDereference,
    InvalidEnumConstruction,
}

impl MirAssertKind {
    /// Constructs the precise implicit predicate for every known rustc assert.
    ///
    /// The extractor persists the returned value in its independently typed
    /// requirement table and attaches that row to [`MirAssertFact`] metadata.
    /// An opaque requirement is intentionally not a variant here: extractors
    /// use [`OpaqueCompilerRequirement`] only when a future or incomplete
    /// compiler representation does not expose one of these known predicates.
    #[must_use]
    pub(crate) fn implicit_requirement(self) -> CompilerAssertRequirement {
        match self {
            Self::BoundsCheck => CompilerAssertRequirement::InBounds(InBoundsRequirement::new()),
            Self::Overflow(operation) => CompilerAssertRequirement::NoOverflow(
                NoOverflowRequirement::new(OverflowOperation::Binary(operation)),
            ),
            Self::OpaqueOverflow => CompilerAssertRequirement::Opaque(
                OpaqueCompilerRequirement::new("the arithmetic operation must not overflow"),
            ),
            Self::OverflowNegation => CompilerAssertRequirement::NoOverflow(
                NoOverflowRequirement::new(OverflowOperation::Negation),
            ),
            Self::DivisionByZero | Self::RemainderByZero => {
                CompilerAssertRequirement::NonZero(NonZeroRequirement::new())
            }
            Self::ResumedAfterReturn => CompilerAssertRequirement::CoroutineState(
                CoroutineStateRequirement::new(CoroutineTerminalState::Returned),
            ),
            Self::ResumedAfterPanic => CompilerAssertRequirement::CoroutineState(
                CoroutineStateRequirement::new(CoroutineTerminalState::Panicked),
            ),
            Self::ResumedAfterDrop => CompilerAssertRequirement::CoroutineState(
                CoroutineStateRequirement::new(CoroutineTerminalState::Dropped),
            ),
            Self::MisalignedPointerDereference => {
                CompilerAssertRequirement::AlignedPointer(AlignedPointerRequirement::new())
            }
            Self::NullPointerDereference => {
                CompilerAssertRequirement::NonNullPointer(NonNullPointerRequirement::new())
            }
            Self::InvalidEnumConstruction => {
                CompilerAssertRequirement::ValidEnum(ValidEnumRequirement::new())
            }
        }
    }

    /// Stable human-facing summary used only by this pack's renderer.
    #[must_use]
    pub(crate) const fn human_description(self) -> &'static str {
        match self {
            Self::BoundsCheck => "index out of bounds",
            Self::Overflow(_) | Self::OpaqueOverflow => "arithmetic overflow",
            Self::OverflowNegation => "negation overflow",
            Self::DivisionByZero => "division by zero",
            Self::RemainderByZero => "remainder with a zero divisor",
            Self::ResumedAfterReturn => "coroutine resumed after returning",
            Self::ResumedAfterPanic => "coroutine resumed after panicking",
            Self::ResumedAfterDrop => "coroutine resumed after being dropped",
            Self::MisalignedPointerDereference => "misaligned pointer dereference",
            Self::NullPointerDereference => "null pointer dereference",
            Self::InvalidEnumConstruction => "invalid enum construction",
        }
    }
}

/// One policy-neutral compiler assertion extracted from MIR.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct MirAssertFact {
    kind: MirAssertKind,
}

impl RowSchema for MirAssertFact {
    const ID: &'static str = "sniff-test.panic.mir-assert";
    const VERSION: u32 = 2;
}

impl FactSchema for MirAssertFact {}

impl MirAssertFact {
    #[must_use]
    pub(crate) const fn new(kind: MirAssertKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> MirAssertKind {
        self.kind
    }
}

/// The assertion site's divisor must not be zero.
///
/// This is intentionally site-relative. The rustc assertion message retains
/// the dividend, not the divisor, so the fact owner and MIR site provide the
/// identity rather than an invented or debug-formatted operand string.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct NonZeroRequirement {}

impl RowSchema for NonZeroRequirement {
    const ID: &'static str = "sniff-test.panic.requirement.non-zero";
    const VERSION: u32 = 1;
}

impl RequirementSchema for NonZeroRequirement {}

impl NonZeroRequirement {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {}
    }
}

/// The assertion site's index must be within its indexed value's length.
///
/// Like [`NonZeroRequirement`], this predicate is site-relative until the MIR
/// collector exposes stable typed value identities.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct InBoundsRequirement {}

impl RowSchema for InBoundsRequirement {
    const ID: &'static str = "sniff-test.panic.requirement.in-bounds";
    const VERSION: u32 = 1;
}

impl RequirementSchema for InBoundsRequirement {}

impl InBoundsRequirement {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {}
    }
}

/// The selected arithmetic operation must not overflow.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct NoOverflowRequirement {
    operation: OverflowOperation,
}

impl RowSchema for NoOverflowRequirement {
    const ID: &'static str = "sniff-test.panic.requirement.no-overflow";
    const VERSION: u32 = 1;
}

impl RequirementSchema for NoOverflowRequirement {}

impl NoOverflowRequirement {
    #[must_use]
    pub(crate) const fn new(operation: OverflowOperation) -> Self {
        Self { operation }
    }

    #[must_use]
    pub(crate) const fn operation(&self) -> OverflowOperation {
        self.operation
    }
}

/// Terminal coroutine state that makes another resume invalid.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CoroutineTerminalState {
    Returned,
    Panicked,
    Dropped,
}

/// The coroutine must not be resumed after the selected terminal state.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct CoroutineStateRequirement {
    terminal_state: CoroutineTerminalState,
}

impl RowSchema for CoroutineStateRequirement {
    const ID: &'static str = "sniff-test.panic.requirement.coroutine-state";
    const VERSION: u32 = 1;
}

impl RequirementSchema for CoroutineStateRequirement {}

impl CoroutineStateRequirement {
    #[must_use]
    pub(crate) const fn new(terminal_state: CoroutineTerminalState) -> Self {
        Self { terminal_state }
    }

    #[must_use]
    pub(crate) const fn terminal_state(&self) -> CoroutineTerminalState {
        self.terminal_state
    }
}

/// The pointer used by an assertion-protected dereference must be aligned.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct AlignedPointerRequirement {}

impl RowSchema for AlignedPointerRequirement {
    const ID: &'static str = "sniff-test.panic.requirement.aligned-pointer";
    const VERSION: u32 = 1;
}

impl RequirementSchema for AlignedPointerRequirement {}

impl AlignedPointerRequirement {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {}
    }
}

/// The pointer used by an assertion-protected dereference must not be null.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct NonNullPointerRequirement {}

impl RowSchema for NonNullPointerRequirement {
    const ID: &'static str = "sniff-test.panic.requirement.non-null-pointer";
    const VERSION: u32 = 1;
}

impl RequirementSchema for NonNullPointerRequirement {}

impl NonNullPointerRequirement {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {}
    }
}

/// The asserted value must encode a valid discriminant for its enum type.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct ValidEnumRequirement {}

impl RowSchema for ValidEnumRequirement {
    const ID: &'static str = "sniff-test.panic.requirement.valid-enum";
    const VERSION: u32 = 1;
}

impl RequirementSchema for ValidEnumRequirement {}

impl ValidEnumRequirement {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {}
    }
}

/// Pack-local construction result for independently typed requirement rows.
///
/// This is not a persisted cross-domain requirement enum. It is a convenience
/// for the MIR assertion collector, which immediately inserts the contained
/// row through the corresponding typed table API.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum CompilerAssertRequirement {
    NonZero(NonZeroRequirement),
    InBounds(InBoundsRequirement),
    NoOverflow(NoOverflowRequirement),
    CoroutineState(CoroutineStateRequirement),
    AlignedPointer(AlignedPointerRequirement),
    NonNullPointer(NonNullPointerRequirement),
    ValidEnum(ValidEnumRequirement),
    Opaque(OpaqueCompilerRequirement),
}

/// Typed fallback when rustc exposes no precise symbolic predicate.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct OpaqueCompilerRequirement {
    description: String,
}

impl RowSchema for OpaqueCompilerRequirement {
    const ID: &'static str = "sniff-test.panic.requirement.opaque-compiler";
    const VERSION: u32 = 1;
}

impl RequirementSchema for OpaqueCompilerRequirement {}

impl OpaqueCompilerRequirement {
    #[must_use]
    pub(crate) fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
        }
    }

    #[must_use]
    pub(crate) fn description(&self) -> &str {
        &self.description
    }
}

/// Root-specific workspace selection of one reachable compiler assertion.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct ReachableMirAssert {
    assertion: ScopedRowRef,
    endpoint: ScopedEntityRef,
    trace: RelationTrace,
    witness_order: u64,
}

impl RowSchema for ReachableMirAssert {
    const ID: &'static str = "sniff-test.panic.reachable-mir-assert";
    const VERSION: u32 = 2;
}

impl DerivedSchema for ReachableMirAssert {}

impl ReachableMirAssert {
    #[must_use]
    pub(crate) const fn new(
        assertion: ScopedRowRef,
        endpoint: ScopedEntityRef,
        trace: RelationTrace,
        witness_order: u64,
    ) -> Self {
        Self {
            assertion,
            endpoint,
            trace,
            witness_order,
        }
    }

    /// Sets the stable order assigned by the root traversal.
    #[must_use]
    pub(crate) const fn with_witness_order(mut self, witness_order: u64) -> Self {
        self.witness_order = witness_order;
        self
    }

    #[must_use]
    pub(crate) const fn assertion(&self) -> &ScopedRowRef {
        &self.assertion
    }

    #[must_use]
    pub(crate) const fn endpoint(&self) -> &ScopedEntityRef {
        &self.endpoint
    }

    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }

    #[must_use]
    pub(crate) const fn witness_order(&self) -> u64 {
        self.witness_order
    }
}

/// Presentation-stable ordering for one exact panic obligation witness.
///
/// The group is deliberately absent: ambiguity groups are an outcome of
/// matching and must never influence which witness represents a claim.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct PanicEvidenceOrdering {
    obligation_source: ScopedRowRef,
    endpoint: ScopedEntityRef,
    trace_target: ScopedEntityRef,
    #[serde(deserialize_with = "deserialize_strict_relation_trace")]
    trace: RelationTrace,
    witness_order: u64,
    semantic_order: EvidenceSemanticOrder,
}

impl RowSchema for PanicEvidenceOrdering {
    const ID: &'static str = "sniff-test.panic.evidence-ordering";
    const VERSION: u32 = 1;
}

impl DerivedSchema for PanicEvidenceOrdering {}

impl PanicEvidenceOrdering {
    #[must_use]
    pub(crate) const fn new(
        obligation_source: ScopedRowRef,
        endpoint: ScopedEntityRef,
        trace_target: ScopedEntityRef,
        trace: RelationTrace,
        witness_order: u64,
        semantic_order: EvidenceSemanticOrder,
    ) -> Self {
        Self {
            obligation_source,
            endpoint,
            trace_target,
            trace,
            witness_order,
            semantic_order,
        }
    }

    #[must_use]
    pub(crate) const fn obligation_source(&self) -> &ScopedRowRef {
        &self.obligation_source
    }

    #[must_use]
    pub(crate) const fn endpoint(&self) -> &ScopedEntityRef {
        &self.endpoint
    }

    #[must_use]
    pub(crate) const fn trace_target(&self) -> &ScopedEntityRef {
        &self.trace_target
    }

    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }

    #[must_use]
    pub(crate) const fn witness_order(&self) -> u64 {
        self.witness_order
    }

    #[must_use]
    pub(crate) const fn semantic_order(&self) -> &EvidenceSemanticOrder {
        &self.semantic_order
    }
}

/// Exact compiler requirement rows discharged by one human claim.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct PanicEvidenceMatch {
    claim: ScopedEntityRef,
    obligation_source: ScopedRowRef,
    endpoint: ScopedEntityRef,
    group: ScopedEntityRef,
    trace: RelationTrace,
    witness_order: u64,
    satisfied_requirements: Vec<ScopedRowRef>,
}

impl RowSchema for PanicEvidenceMatch {
    const ID: &'static str = "sniff-test.panic.evidence-match";
    const VERSION: u32 = 4;
}

impl DerivedSchema for PanicEvidenceMatch {}

impl PanicEvidenceMatch {
    #[must_use]
    pub(crate) fn new(
        claim: ScopedEntityRef,
        obligation_source: ScopedRowRef,
        endpoint: ScopedEntityRef,
        group: ScopedEntityRef,
        trace: RelationTrace,
        witness_order: u64,
        mut satisfied_requirements: Vec<ScopedRowRef>,
    ) -> Self {
        satisfied_requirements.sort();
        satisfied_requirements.dedup();
        Self {
            claim,
            obligation_source,
            endpoint,
            group,
            trace,
            witness_order,
            satisfied_requirements,
        }
    }

    #[must_use]
    pub(crate) const fn claim(&self) -> &ScopedEntityRef {
        &self.claim
    }

    #[must_use]
    pub(crate) const fn obligation_source(&self) -> &ScopedRowRef {
        &self.obligation_source
    }

    #[must_use]
    pub(crate) const fn endpoint(&self) -> &ScopedEntityRef {
        &self.endpoint
    }

    #[must_use]
    pub(crate) const fn group(&self) -> &ScopedEntityRef {
        &self.group
    }

    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }

    #[must_use]
    pub(crate) const fn witness_order(&self) -> u64 {
        self.witness_order
    }

    #[must_use]
    pub(crate) fn satisfied_requirements(&self) -> &[ScopedRowRef] {
        &self.satisfied_requirements
    }
}

/// A reachable compiler assertion still has undischargeable requirements.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct UnsatisfiedCompilerAssertIssue {
    assertion: ScopedRowRef,
    endpoint: ScopedEntityRef,
    kind: MirAssertKind,
    witness_order: u64,
    missing_requirements: Vec<ScopedRowRef>,
}

impl RowSchema for UnsatisfiedCompilerAssertIssue {
    const ID: &'static str = "sniff-test.panic.unsatisfied-compiler-assert";
    const VERSION: u32 = 2;
}

impl IssueSchema for UnsatisfiedCompilerAssertIssue {}

impl UnsatisfiedCompilerAssertIssue {
    #[must_use]
    pub(crate) fn new(
        assertion: ScopedRowRef,
        endpoint: ScopedEntityRef,
        kind: MirAssertKind,
        witness_order: u64,
        mut missing_requirements: Vec<ScopedRowRef>,
    ) -> Self {
        missing_requirements.sort();
        missing_requirements.dedup();
        Self {
            assertion,
            endpoint,
            kind,
            witness_order,
            missing_requirements,
        }
    }

    #[must_use]
    pub(crate) const fn assertion(&self) -> &ScopedRowRef {
        &self.assertion
    }

    #[must_use]
    pub(crate) const fn endpoint(&self) -> &ScopedEntityRef {
        &self.endpoint
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> MirAssertKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn witness_order(&self) -> u64 {
        self.witness_order
    }

    #[must_use]
    pub(crate) fn missing_requirements(&self) -> &[ScopedRowRef] {
        &self.missing_requirements
    }
}
