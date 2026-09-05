//! Direct, versioned, policy-neutral facts persisted for cross-crate tracing.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

pub(crate) use crate::namespace::{StableDefPathHash, StableInstanceHash};

/// Policy-neutral facts extracted from one rustc artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ArtifactFacts {
    pub(crate) functions: Vec<FunctionFact>,
    pub(crate) source_files: Vec<SourceFileFact>,
}

impl ArtifactFacts {
    /// Builds validated facts in their deterministic serialized order.
    pub(crate) fn new(
        functions: Vec<FunctionFact>,
        source_files: Vec<SourceFileFact>,
    ) -> Result<Self, ArtifactValidationError> {
        let mut artifact = Self {
            functions,
            source_files,
        };
        artifact.canonicalize();
        artifact.validate()?;
        Ok(artifact)
    }

    /// Sorts set-like collections and removes duplicates where identity is not
    /// itself a fact. Duplicate function, source, and local-fact identities are
    /// retained so [`Self::validate`] can reject them.
    pub(crate) fn canonicalize(&mut self) {
        self.source_files
            .sort_by(|left, right| left.id.cmp(&right.id));
        self.functions.sort_by_key(|body| body.function);
        for body in &mut self.functions {
            canonicalize_attributes(&mut body.attributes);
            if let Some(declaration) = &mut body.contract_declaration {
                canonicalize_function_target(declaration);
            }
            body.calls.sort_by_key(|call| call.id);
            body.effects.sort_by_key(|effect| effect.id);
            body.markers.sort_by_key(|marker| marker.id);
            body.unverified_marker_probes.sort();

            for call in &mut body.calls {
                if let Some(target) = &mut call.declaration_target {
                    canonicalize_function_target(target);
                }
                canonicalize_call_target(&mut call.target);
            }
            for marker in &mut body.markers {
                sort_and_deduplicate(&mut marker.applicable_probing);
            }
        }
    }

    /// Checks structural integrity and canonical ordering after deserialization.
    pub(crate) fn validate(&self) -> Result<(), ArtifactValidationError> {
        validate_sorted_unique(
            &self.source_files,
            |file| file.id.clone(),
            "source file identity",
        )?;
        let mut source_lengths = BTreeMap::new();
        for source in &self.source_files {
            require_nonempty(source.id.as_str(), "source file ID")?;
            require_nonempty(&source.filename, "source filename")?;
            require_nonempty(&source.content_hash, "source content hash")?;
            source_lengths.insert(&source.id, source.byte_len);
        }

        validate_sorted_unique(&self.functions, |body| body.function, "function identity")?;
        for body in &self.functions {
            validate_body(body, &source_lengths)?;
        }
        Ok(())
    }

    /// Resolves an exact function body, falling back to the generic definition
    /// only when no matching exact body satisfies the lookup.
    #[must_use]
    pub(crate) fn function_body(&self, function: FunctionId) -> Option<&FunctionFact> {
        self.function_body_matching(function, |_| true)
    }

    /// Resolves only facts extracted by the function's defining artifact.
    ///
    /// A consumer-instantiation overlay takes precedence for ordinary lookup,
    /// but does not hide a generic defining body from this lookup.
    #[must_use]
    pub(crate) fn defining_function_body(&self, function: FunctionId) -> Option<&FunctionFact> {
        self.function_body_matching(function, |body| {
            matches!(body.provenance, FunctionFactProvenance::DefiningArtifact)
        })
    }

    /// Unions every observed namespace alias for each stable definition.
    ///
    /// Bodies and target metadata can describe the same definition through
    /// different re-export or session paths. Policy consumers must choose from
    /// the complete definition-level candidate set instead of letting artifact
    /// occurrence order choose a path implicitly.
    #[must_use]
    pub(crate) fn definition_namespace_index(&self) -> DefinitionNamespaceIndex {
        let mut candidates = BTreeMap::<StableDefPathHash, BTreeSet<String>>::new();
        for body in &self.functions {
            extend_definition_namespace_candidates(
                &mut candidates,
                body.function,
                &body.attributes.namespace_candidates,
            );
            if let Some(declaration) = &body.contract_declaration {
                extend_target_namespace_candidates(&mut candidates, declaration);
            }
            for call in &body.calls {
                if let Some(target) = call.target.function_target() {
                    extend_target_namespace_candidates(&mut candidates, target);
                }
                if let Some(declaration) = &call.declaration_target {
                    extend_target_namespace_candidates(&mut candidates, declaration);
                }
            }
        }
        DefinitionNamespaceIndex {
            candidates: candidates
                .into_iter()
                .map(|(definition, candidates)| (definition, candidates.into_iter().collect()))
                .collect(),
        }
    }

    /// Resolves source evidence from the defining body when one is available.
    /// Consumer-instantiation overlays provide call topology, but must not
    /// replace the defining artifact's observation of its own source.
    #[must_use]
    pub(crate) fn source_marker_evidence_state(
        &self,
        function: FunctionId,
        kind: AnnotationFactKind,
        target: AnnotationTargetFact,
        probing: AnnotationProbingFact,
    ) -> Option<MarkerEvidenceState> {
        let selected = self.function_body(function)?;
        if let Some(defining) = self.defining_function_body(function) {
            if std::ptr::eq(selected, defining) {
                return defining.marker_evidence_state(kind, target, probing);
            }
            let (matched, evidence) =
                projected_marker_evidence(selected, defining, kind, target, probing);
            if matched {
                return evidence;
            }
        }
        selected.marker_evidence_state(kind, target, probing)
    }

    fn function_body_matching(
        &self,
        function: FunctionId,
        predicate: impl Fn(&FunctionFact) -> bool,
    ) -> Option<&FunctionFact> {
        function.resolution_candidates().find_map(|candidate| {
            let index = self
                .functions
                .binary_search_by_key(&candidate, |body| body.function)
                .ok()?;
            let body = &self.functions[index];
            predicate(body).then_some(body)
        })
    }
}

/// Every namespace path observed for one stable function definition.
///
/// Compiler sessions and re-exports can expose the same definition through
/// different paths. Policy interpretation must use this definition-level view
/// so an arbitrary body or call-target occurrence cannot decide the boundary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DefinitionNamespaceIndex {
    candidates: BTreeMap<StableDefPathHash, Vec<String>>,
}

impl DefinitionNamespaceIndex {
    #[must_use]
    pub(crate) fn candidates(&self, function: FunctionId) -> &[String] {
        self.candidates
            .get(&function.def_path_hash)
            .map_or(&[], Vec::as_slice)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&StableDefPathHash, &[String])> + '_ {
        self.candidates
            .iter()
            .map(|(definition, candidates)| (definition, candidates.as_slice()))
    }
}

fn extend_target_namespace_candidates(
    candidates: &mut BTreeMap<StableDefPathHash, BTreeSet<String>>,
    target: &FunctionTargetFact,
) {
    extend_definition_namespace_candidates(
        candidates,
        target.function,
        &target.attributes.namespace_candidates,
    );
}

fn extend_definition_namespace_candidates(
    candidates: &mut BTreeMap<StableDefPathHash, BTreeSet<String>>,
    function: FunctionId,
    observed: &[String],
) {
    candidates
        .entry(function.def_path_hash)
        .or_default()
        .extend(observed.iter().cloned());
}

fn projected_marker_evidence(
    selected: &FunctionFact,
    defining: &FunctionFact,
    kind: AnnotationFactKind,
    target: AnnotationTargetFact,
    probing: AnnotationProbingFact,
) -> (bool, Option<MarkerEvidenceState>) {
    match target {
        AnnotationTargetFact::Call(id) => {
            let Some(selected_call) = selected.calls.iter().find(|call| call.id == id) else {
                return (false, None);
            };
            aggregate_marker_evidence(
                defining,
                kind,
                defining
                    .calls
                    .iter()
                    .filter(|call| same_call_source_site(call, selected_call))
                    .map(|call| AnnotationTargetFact::Call(call.id)),
                probing,
            )
        }
        AnnotationTargetFact::Effect(id) => {
            let Some(selected_effect) = selected.effects.iter().find(|effect| effect.id == id)
            else {
                return (false, None);
            };
            aggregate_marker_evidence(
                defining,
                kind,
                defining
                    .effects
                    .iter()
                    .filter(|effect| same_effect_source_site(effect, selected_effect))
                    .map(|effect| AnnotationTargetFact::Effect(effect.id)),
                probing,
            )
        }
        AnnotationTargetFact::Function(_) => (false, None),
    }
}

fn aggregate_marker_evidence(
    body: &FunctionFact,
    kind: AnnotationFactKind,
    targets: impl Iterator<Item = AnnotationTargetFact>,
    probing: AnnotationProbingFact,
) -> (bool, Option<MarkerEvidenceState>) {
    let mut matched = false;
    let mut aggregate: Option<MarkerEvidenceState> = None;
    for target in targets {
        if let Some(evidence) = body.marker_evidence_state(kind, target, probing) {
            matched = true;
            aggregate = Some(match aggregate {
                Some(prior) => prior.merge(evidence),
                None => evidence,
            });
        }
    }
    (matched, aggregate)
}

pub(crate) fn same_call_source_site(left: &CallFact, right: &CallFact) -> bool {
    has_stable_call_source_site(left)
        && has_stable_call_source_site(right)
        && left.source_range == right.source_range
        && left.expanded_range == right.expanded_range
        && left.callee_range == right.callee_range
        && same_macro_provenance(&left.macro_expansions, &right.macro_expansions)
}

fn same_effect_source_site(left: &EffectFact, right: &EffectFact) -> bool {
    has_stable_effect_source_site(left)
        && has_stable_effect_source_site(right)
        && left.kind == right.kind
        && left.source_range == right.source_range
        && left.expanded_range == right.expanded_range
        && same_macro_provenance(&left.macro_expansions, &right.macro_expansions)
}

fn has_stable_call_source_site(call: &CallFact) -> bool {
    call.source_range.is_some()
        || call.expanded_range.is_some()
        || call.callee_range.is_some()
        || call
            .macro_expansions
            .iter()
            .any(|frame| frame.source_range.is_some())
}

fn has_stable_effect_source_site(effect: &EffectFact) -> bool {
    effect.source_range.is_some()
        || effect.expanded_range.is_some()
        || effect
            .macro_expansions
            .iter()
            .any(|frame| frame.source_range.is_some())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArtifactValidationError {
    message: String,
}

impl ArtifactValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ArtifactValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ArtifactValidationError {}

/// Stable identity for a generic definition or one exact rustc instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct FunctionId {
    pub(crate) def_path_hash: StableDefPathHash,
    pub(crate) instance_hash: Option<StableInstanceHash>,
}

impl FunctionId {
    #[must_use]
    pub(crate) const fn generic(def_path_hash: StableDefPathHash) -> Self {
        Self {
            def_path_hash,
            instance_hash: None,
        }
    }

    #[must_use]
    pub(crate) const fn exact(
        def_path_hash: StableDefPathHash,
        instance_hash: StableInstanceHash,
    ) -> Self {
        Self {
            def_path_hash,
            instance_hash: Some(instance_hash),
        }
    }

    /// Yields lookup identities in precedence order: the requested identity,
    /// followed by its generic definition when the request is exact.
    pub(crate) fn resolution_candidates(self) -> impl Iterator<Item = Self> {
        std::iter::once(self).chain(
            self.instance_hash
                .map(|_| Self::generic(self.def_path_hash)),
        )
    }
}

/// Complete extracted body facts for one function identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct FunctionFact {
    pub(crate) function: FunctionId,
    /// Why this artifact owns the serialized body facts.
    pub(crate) provenance: FunctionFactProvenance,
    pub(crate) display_path: String,
    pub(crate) attributes: FunctionAttributesFact,
    /// Trait/interface declaration whose contract is the fallback for this
    /// implementation when the implementation has none in a domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) contract_declaration: Option<FunctionTargetFact>,
    pub(crate) source_range: Option<SourceRangeFact>,
    pub(crate) calls: Vec<CallFact>,
    pub(crate) effects: Vec<EffectFact>,
    pub(crate) markers: Vec<AnnotationFact>,
    /// Sparse negative probe facts. Present markers remain represented by
    /// [`AnnotationFact`], while the absence of both records is verified
    /// absence under this cache format's complete-probing invariant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) unverified_marker_probes: Vec<UnverifiedMarkerProbeFact>,
}

impl FunctionFact {
    #[must_use]
    pub(crate) fn marker_evidence_state(
        &self,
        kind: AnnotationFactKind,
        target: AnnotationTargetFact,
        probing: AnnotationProbingFact,
    ) -> Option<MarkerEvidenceState> {
        if !self.has_marker_probe_key(kind, target) {
            return None;
        }
        if self.markers.iter().any(|marker| {
            marker.kind == kind
                && marker.target == target
                && marker.applicable_probing.contains(&probing)
        }) {
            Some(MarkerEvidenceState::Present)
        } else if let Some(probe) = self
            .unverified_marker_probes
            .iter()
            .find(|probe| probe.kind == kind && probe.target == target && probe.probing == probing)
        {
            Some(MarkerEvidenceState::Unverified(probe.reason))
        } else {
            Some(MarkerEvidenceState::VerifiedAbsent)
        }
    }

    fn has_marker_probe_key(&self, kind: AnnotationFactKind, target: AnnotationTargetFact) -> bool {
        match (kind, target) {
            (AnnotationFactKind::PanicJustification, AnnotationTargetFact::Call(id)) => self
                .calls
                .iter()
                .find(|call| call.id == id)
                .is_some_and(|call| call.kind != CallKindFact::Assert),
            (AnnotationFactKind::SafetyJustification, AnnotationTargetFact::Call(id)) => {
                self.calls.iter().any(|call| call.id == id)
            }
            (AnnotationFactKind::PanicJustification, AnnotationTargetFact::Effect(id)) => self
                .effects
                .iter()
                .find(|effect| effect.id == id)
                .is_some_and(|effect| matches!(effect.kind, EffectFactKind::CompilerAssert { .. })),
            (AnnotationFactKind::SafetyJustification, AnnotationTargetFact::Effect(id)) => self
                .effects
                .iter()
                .find(|effect| effect.id == id)
                .is_some_and(|effect| {
                    matches!(effect.kind, EffectFactKind::UnsafeOperation { .. })
                }),
            (
                AnnotationFactKind::PanicContract
                | AnnotationFactKind::SafetyContract
                | AnnotationFactKind::PanicJustification
                | AnnotationFactKind::SafetyJustification,
                AnnotationTargetFact::Function(_),
            )
            | (
                AnnotationFactKind::PanicContract | AnnotationFactKind::SafetyContract,
                AnnotationTargetFact::Call(_) | AnnotationTargetFact::Effect(_),
            ) => false,
        }
    }
}

/// Provenance for one body in an artifact facts.
///
/// Most bodies are definitions owned by the artifact's crate. A consumer
/// overlay instead records rustc's exact monomorphized view of a definition
/// from another crate, including dispatch choices that can depend on types and
/// impls from the consuming crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub(crate) enum FunctionFactProvenance {
    DefiningArtifact,
    ConsumerInstantiation { consumer_stable_crate_id: u64 },
}

/// Function metadata needed for root selection and policy interpretation.
#[allow(
    clippy::struct_excessive_bools,
    reason = "these independent compiler facts are serialized facts fields, not mutually exclusive state"
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct FunctionAttributesFact {
    pub(crate) is_unsafe: bool,
    pub(crate) is_exported: bool,
    /// Whether the definition provides a Rust body that an owning artifact facts
    /// is expected to contain. Required trait methods and foreign
    /// declarations are intentional graph boundaries.
    pub(crate) has_rust_body: bool,
    /// The declaration belongs to the current crate but has no Rust body.
    ///
    /// Foreign calls remain policy-neutral call facts. They may still require
    /// a safety justification or match an explicit panic boundary policy, but
    /// absence of a Rust MIR body is intentional rather than incomplete facts.
    pub(crate) is_foreign: bool,
    pub(crate) namespace_candidates: Vec<String>,
}

/// Stable source-file identity and integrity metadata.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct SourceFileId(String);

impl SourceFileId {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct SourceFileFact {
    pub(crate) id: SourceFileId,
    pub(crate) filename: String,
    pub(crate) content_hash: String,
    pub(crate) byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct SourceRangeFact {
    pub(crate) file: SourceFileId,
    pub(crate) byte_start: u64,
    pub(crate) byte_end: u64,
}

macro_rules! local_id {
    ($name:ident) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub(crate) struct $name(u32);

        impl $name {
            #[must_use]
            pub(crate) const fn new(value: u32) -> Self {
                Self(value)
            }
        }
    };
}

local_id!(CallId);
local_id!(CallSiteId);
local_id!(EffectId);
local_id!(MarkerId);
local_id!(SafetyEffectGroupId);

macro_rules! local_index {
    ($name:ident) => {
        impl $name {
            #[must_use]
            pub(crate) const fn index(self) -> u32 {
                self.0
            }
        }
    };
}

local_index!(CallId);
local_index!(CallSiteId);
local_index!(EffectId);
local_index!(MarkerId);

/// One graph edge emitted while expanding a function body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct CallFact {
    pub(crate) id: CallId,
    /// Artifact-local identity of one source call occurrence. Multiple raw
    /// edges for the same invocation share this value.
    pub(crate) call_site: CallSiteId,
    pub(crate) kind: CallKindFact,
    /// Artifact-local identity of the source-level THIR unsafe scope (or
    /// standalone call site) that owns this potential safety effect.
    pub(crate) safety_effect_group: Option<SafetyEffectGroupId>,
    /// Whether invoking this call target requires an unsafe context.
    ///
    /// This remains explicit even for opaque function-pointer calls, where no
    /// concrete [`FunctionTargetFact`] exists to carry the function signature.
    pub(crate) requires_unsafe: bool,
    /// Whether rustc inserted the call inside a `BuiltinUnsafe` block.
    ///
    /// Such a call can still target an unsafe function, but its unsafe context
    /// is the compiler's responsibility rather than a user justification
    /// obligation. Consumer-instantiation overlays reconcile this fact from
    /// the defining artifact.
    pub(crate) inside_builtin_unsafe: bool,
    /// Preferred presentation location. For macro-expanded calls this is the
    /// outermost available invocation site.
    pub(crate) source_range: Option<SourceRangeFact>,
    /// The semantic call location after macro expansion. This remains
    /// separate from presentation provenance so exact call reconciliation is
    /// stable across workspace and dependency artifacts.
    pub(crate) expanded_range: Option<SourceRangeFact>,
    /// Ordered outermost-to-innermost macro expansions that produced this
    /// semantic call.
    pub(crate) macro_expansions: Vec<MacroExpansionFact>,
    pub(crate) callee_range: Option<SourceRangeFact>,
    /// Invocation-local classification for an unresolved indirect call.
    ///
    /// This deliberately carries no erased type or trait key: compatible
    /// callables observed elsewhere are not proof that they target this call.
    pub(crate) indirect_kind: Option<IndirectCallKindFact>,
    /// Trait/interface declaration retained from THIR when every matched raw
    /// call fact agrees on one definition.
    ///
    /// Trait calls retain their declaration here even when [`Self::target`]
    /// resolves to a concrete impl. Interpretation prefers the impl's contract
    /// and falls back to this declaration contract. This metadata never changes
    /// traversal.
    pub(crate) declaration_target: Option<FunctionTargetFact>,
    pub(crate) target: CallTargetFact,
}

/// One macro definition and source invocation on the path to a semantic fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct MacroExpansionFact {
    pub(crate) macro_def: StableDefPathHash,
    pub(crate) display_path: String,
    pub(crate) source_range: Option<SourceRangeFact>,
}

pub(crate) fn same_macro_provenance(
    left: &[MacroExpansionFact],
    right: &[MacroExpansionFact],
) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.macro_def == right.macro_def && left.source_range == right.source_range
        })
}

/// Minimal edge classes retained by effect interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CallKindFact {
    DirectCall,
    TailCall,
    MacroExpansion,
    ConstBody,
    CoroutineBody,
    Assert,
    IndirectCall,
}

/// Compiler classification of one unresolved invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum IndirectCallKindFact {
    FunctionPointer,
    DynamicDispatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "target")]
pub(crate) enum CallTargetFact {
    Function(FunctionTargetFact),
    OpaqueBoundary {
        description: String,
        target: Option<OpaqueTargetFact>,
    },
}

impl CallTargetFact {
    /// Returns the stable callable metadata carried by this target, if any.
    #[must_use]
    pub(crate) fn function_target(&self) -> Option<&FunctionTargetFact> {
        match self {
            Self::Function(target) => Some(target),
            Self::OpaqueBoundary { target, .. } => {
                target.as_ref().map(OpaqueTargetFact::function_target)
            }
        }
    }
}

/// Optional stable identity retained for an otherwise opaque boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "target")]
pub(crate) enum OpaqueTargetFact {
    Trait(FunctionTargetFact),
    Function(FunctionTargetFact),
}

impl OpaqueTargetFact {
    fn function_target(&self) -> &FunctionTargetFact {
        match self {
            Self::Trait(target) | Self::Function(target) => target,
        }
    }
}

/// Stable callee metadata sufficient for policy interpretation without a body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct FunctionTargetFact {
    pub(crate) function: FunctionId,
    pub(crate) display_path: String,
    pub(crate) attributes: FunctionAttributesFact,
    pub(crate) contracts: FunctionContractsFact,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct FunctionContractsFact {
    pub(crate) panic: Option<ContractFact>,
    pub(crate) safety: Option<ContractFact>,
}

/// Raw documented contract, before any requirement satisfaction is interpreted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ContractFact {
    pub(crate) source_range: Option<SourceRangeFact>,
    pub(crate) requirements: Vec<ContractRequirementFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ContractRequirementFact {
    pub(crate) name: String,
    pub(crate) condition: String,
    pub(crate) structural_path: Vec<usize>,
    pub(crate) source_range: Option<SourceRangeFact>,
}

/// One raw effect site in a function body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct EffectFact {
    pub(crate) id: EffectId,
    /// Present exactly for safety effects, where multiple runtime operations
    /// can belong to one source-level unsafe scope.
    pub(crate) safety_effect_group: Option<SafetyEffectGroupId>,
    /// Preferred presentation location, normally the outermost macro
    /// invocation when the effect was expanded from a macro.
    pub(crate) source_range: Option<SourceRangeFact>,
    /// The semantic effect location after macro expansion.
    pub(crate) expanded_range: Option<SourceRangeFact>,
    /// Ordered outermost-to-innermost macro expansions that produced the
    /// semantic effect.
    pub(crate) macro_expansions: Vec<MacroExpansionFact>,
    pub(crate) kind: EffectFactKind,
}

/// Stable semantic subtype for a compiler-generated MIR assertion.
///
/// The variant set mirrors rustc's assertion kinds without persisting MIR
/// operands or applying lint policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CompilerAssertKind {
    BoundsCheck,
    Overflow,
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

impl CompilerAssertKind {
    /// Stable human-facing description of this compiler assertion.
    #[must_use]
    pub(crate) const fn human_description(self) -> &'static str {
        match self {
            Self::BoundsCheck => "index out of bounds",
            Self::Overflow => "arithmetic overflow",
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

/// Stable subtype for a non-call operation that rustc requires to occur in an
/// unsafe context.
///
/// The variant set is pinned to the toolchain's unsafety checker. Compiler
/// probing maps rustc operations into this versioned artifact vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SafetyOpKind {
    #[serde(rename = "raw-pointer-dereference")]
    DerefRawPointer,
    #[serde(rename = "mutable-static-access")]
    UseOfMutableStatic,
    #[serde(rename = "extern-static-access")]
    UseOfExternStatic,
    #[serde(rename = "union-field-access")]
    AccessToUnionField,
    #[serde(rename = "unsafe-field-access")]
    UseOfUnsafeField,
    #[serde(rename = "layout-constrained-type-initialization")]
    InitializingLayoutConstrainedType,
    #[serde(rename = "unsafe-field-initialization")]
    InitializingTypeWithUnsafeField,
    #[serde(rename = "layout-constrained-field-mutation")]
    MutationOfLayoutConstrainedField,
    #[serde(rename = "layout-constrained-field-borrow")]
    BorrowOfLayoutConstrainedField,
    InlineAssembly,
    UnsafeBinderCast,
}

impl SafetyOpKind {
    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::DerefRawPointer => "raw pointer dereference",
            Self::UseOfMutableStatic => "mutable static access",
            Self::UseOfExternStatic => "extern static access",
            Self::AccessToUnionField => "union field access",
            Self::UseOfUnsafeField => "unsafe field access",
            Self::InitializingLayoutConstrainedType => "layout-constrained type initialization",
            Self::InitializingTypeWithUnsafeField => "unsafe field initialization",
            Self::MutationOfLayoutConstrainedField => "layout-constrained field mutation",
            Self::BorrowOfLayoutConstrainedField => "layout-constrained field borrow",
            Self::InlineAssembly => "inline assembly",
            Self::UnsafeBinderCast => "unsafe binder cast",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "effect")]
pub(crate) enum EffectFactKind {
    CompilerAssert { kind: CompilerAssertKind },
    UnsafeOperation { kind: SafetyOpKind },
}

/// One source marker and the fact it was associated with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct AnnotationFact {
    pub(crate) id: MarkerId,
    /// Identity of one logical marker occurrence. A marker in a macro
    /// definition has a distinct identity for each expansion, while the same
    /// occurrence projected into generic and concrete bodies shares it.
    pub(crate) identity: String,
    pub(crate) kind: AnnotationFactKind,
    pub(crate) source_range: Option<SourceRangeFact>,
    pub(crate) target: AnnotationTargetFact,
    pub(crate) applicable_probing: Vec<AnnotationProbingFact>,
    pub(crate) satisfactions: Vec<AnnotationSatisfactionFact>,
    pub(crate) requirements: Vec<ContractRequirementFact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AnnotationFactKind {
    PanicJustification,
    SafetyJustification,
    PanicContract,
    SafetyContract,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "target")]
pub(crate) enum AnnotationTargetFact {
    Function(FunctionId),
    Call(CallId),
    Effect(EffectId),
}

/// Marker-probing strategies in which an extracted association applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AnnotationProbingFact {
    SourceCallsite,
    MacroDefinitionFirst,
}

/// Normalized three-state source evidence exposed to policy consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MarkerEvidenceState {
    Present,
    VerifiedAbsent,
    Unverified(UnverifiedMarkerProbeReason),
}

/// Why source inspection could not establish marker presence or absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum UnverifiedMarkerProbeReason {
    NoUsableSourceSpan,
    SourceUnavailable,
}

impl UnverifiedMarkerProbeReason {
    /// Conservatively combines observations for one logical probe key.
    #[must_use]
    pub(crate) fn merge(self, other: Self) -> Self {
        if matches!(self, Self::SourceUnavailable) || matches!(other, Self::SourceUnavailable) {
            Self::SourceUnavailable
        } else {
            Self::NoUsableSourceSpan
        }
    }
}

impl MarkerEvidenceState {
    #[must_use]
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::Present, _) | (_, Self::Present) => Self::Present,
            (Self::Unverified(left), Self::Unverified(right)) => {
                Self::Unverified(left.merge(right))
            }
            (unverified @ Self::Unverified(_), Self::VerifiedAbsent)
            | (Self::VerifiedAbsent, unverified @ Self::Unverified(_)) => unverified,
            (Self::VerifiedAbsent, Self::VerifiedAbsent) => Self::VerifiedAbsent,
        }
    }
}

/// One source marker lookup that could not prove presence or absence.
///
/// This is deliberately sparse: successful markers live in [`AnnotationFact`]
/// and verified absence is inferred when neither kind of record exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct UnverifiedMarkerProbeFact {
    pub(crate) kind: AnnotationFactKind,
    pub(crate) target: AnnotationTargetFact,
    pub(crate) probing: AnnotationProbingFact,
    pub(crate) reason: UnverifiedMarkerProbeReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct AnnotationSatisfactionFact {
    pub(crate) requirement: Option<String>,
    pub(crate) reason: String,
    pub(crate) structural_path: Option<Vec<usize>>,
}

fn canonicalize_attributes(attributes: &mut FunctionAttributesFact) {
    sort_and_deduplicate(&mut attributes.namespace_candidates);
}

fn canonicalize_call_target(target: &mut CallTargetFact) {
    match target {
        CallTargetFact::Function(target) => canonicalize_function_target(target),
        CallTargetFact::OpaqueBoundary {
            target: Some(target),
            ..
        } => match target {
            OpaqueTargetFact::Trait(target) | OpaqueTargetFact::Function(target) => {
                canonicalize_function_target(target);
            }
        },
        CallTargetFact::OpaqueBoundary { target: None, .. } => {}
    }
}

fn canonicalize_function_target(target: &mut FunctionTargetFact) {
    canonicalize_attributes(&mut target.attributes);
}

fn sort_and_deduplicate<T: Ord>(values: &mut Vec<T>) {
    values.sort();
    values.dedup();
}

fn validate_body(
    body: &FunctionFact,
    source_lengths: &BTreeMap<&SourceFileId, u64>,
) -> Result<(), ArtifactValidationError> {
    require_nonempty(&body.display_path, "function display path")?;
    if matches!(
        body.provenance,
        FunctionFactProvenance::ConsumerInstantiation { .. }
    ) && body.function.instance_hash.is_none()
    {
        return Err(ArtifactValidationError::new(
            "consumer-instantiation overlay must have an exact function identity",
        ));
    }
    validate_attributes(&body.attributes)?;
    if let Some(declaration) = &body.contract_declaration {
        validate_function_target(declaration, source_lengths)?;
        if declaration.function.def_path_hash == body.function.def_path_hash {
            return Err(ArtifactValidationError::new(
                "function contract declaration refers to the function itself",
            ));
        }
    }
    if !body.attributes.has_rust_body {
        return Err(ArtifactValidationError::new(
            "function body is marked as a bodyless declaration",
        ));
    }
    validate_optional_range(body.source_range.as_ref(), source_lengths)?;

    validate_sorted_unique(&body.calls, |call| call.id, "call ID")?;
    for call in &body.calls {
        if call.safety_effect_group.is_none() {
            return Err(ArtifactValidationError::new(format!(
                "call {} has no safety effect group",
                call.id.index()
            )));
        }
        validate_optional_range(call.source_range.as_ref(), source_lengths)?;
        validate_optional_range(call.expanded_range.as_ref(), source_lengths)?;
        validate_macro_expansions(&call.macro_expansions, source_lengths)?;
        validate_optional_range(call.callee_range.as_ref(), source_lengths)?;
        if call.indirect_kind.is_some() && call.kind != CallKindFact::IndirectCall {
            return Err(ArtifactValidationError::new(format!(
                "non-indirect call {} has an indirect-call classification",
                call.id.index()
            )));
        }
        if let Some(target) = &call.declaration_target {
            validate_function_target(target, source_lengths)?;
        }
        validate_call_target(&call.target, source_lengths)?;
    }

    validate_sorted_unique(&body.effects, |effect| effect.id, "effect ID")?;
    for effect in &body.effects {
        validate_optional_range(effect.source_range.as_ref(), source_lengths)?;
        validate_optional_range(effect.expanded_range.as_ref(), source_lengths)?;
        validate_macro_expansions(&effect.macro_expansions, source_lengths)?;
        match &effect.kind {
            EffectFactKind::CompilerAssert { .. } => {
                if effect.safety_effect_group.is_some() {
                    return Err(ArtifactValidationError::new(format!(
                        "compiler assertion effect {} has a safety effect group",
                        effect.id.index()
                    )));
                }
            }
            EffectFactKind::UnsafeOperation { .. } if effect.safety_effect_group.is_none() => {
                return Err(ArtifactValidationError::new(format!(
                    "unsafe operation effect {} has no safety effect group",
                    effect.id.index()
                )));
            }
            EffectFactKind::UnsafeOperation { .. } => {}
        }
    }

    validate_sorted_unique(&body.markers, |marker| marker.id, "marker ID")?;
    for marker in &body.markers {
        require_nonempty(&marker.identity, "marker identity")?;
        validate_optional_range(marker.source_range.as_ref(), source_lengths)?;
        validate_nonempty_sorted_set(&marker.applicable_probing, "marker probing applicability")?;
        validate_marker_target(body, marker)?;
        for satisfaction in &marker.satisfactions {
            if let Some(requirement) = &satisfaction.requirement {
                require_nonempty(requirement, "marker satisfaction requirement")?;
            }
            require_nonempty(&satisfaction.reason, "marker satisfaction reason")?;
            if satisfaction.requirement.is_none()
                && satisfaction
                    .structural_path
                    .as_ref()
                    .is_some_and(Vec::is_empty)
            {
                return Err(ArtifactValidationError::new(
                    "marker satisfaction structural path is empty",
                ));
            }
        }
        validate_requirements(&marker.requirements, source_lengths)?;
    }

    validate_unverified_marker_probes(body)?;

    Ok(())
}

fn validate_unverified_marker_probes(body: &FunctionFact) -> Result<(), ArtifactValidationError> {
    validate_sorted_unique(
        &body.unverified_marker_probes,
        |probe| (probe.kind, probe.target, probe.probing),
        "unverified marker probe",
    )?;
    for probe in &body.unverified_marker_probes {
        if !matches!(
            probe.kind,
            AnnotationFactKind::PanicJustification | AnnotationFactKind::SafetyJustification
        ) {
            return Err(ArtifactValidationError::new(
                "unverified marker probe must describe a justification",
            ));
        }
        validate_unverified_marker_probe_target(body, probe)?;
        if !body.has_marker_probe_key(probe.kind, probe.target) {
            return Err(ArtifactValidationError::new(
                "unverified marker probe does not describe an extracted probe key",
            ));
        }
        if body.markers.iter().any(|marker| {
            marker.kind == probe.kind
                && marker.target == probe.target
                && marker.applicable_probing.contains(&probe.probing)
        }) {
            return Err(ArtifactValidationError::new(
                "marker probe is both present and unverified",
            ));
        }
    }

    Ok(())
}

fn validate_unverified_marker_probe_target(
    body: &FunctionFact,
    probe: &UnverifiedMarkerProbeFact,
) -> Result<(), ArtifactValidationError> {
    match probe.target {
        AnnotationTargetFact::Function(_) => Err(ArtifactValidationError::new(
            "unverified marker probe has a function target",
        )),
        AnnotationTargetFact::Call(call)
            if body
                .calls
                .binary_search_by_key(&call, |candidate| candidate.id)
                .is_err() =>
        {
            Err(ArtifactValidationError::new(format!(
                "unverified marker probe has a dangling call target {}",
                call.index()
            )))
        }
        AnnotationTargetFact::Effect(effect)
            if body
                .effects
                .binary_search_by_key(&effect, |candidate| candidate.id)
                .is_err() =>
        {
            Err(ArtifactValidationError::new(format!(
                "unverified marker probe has a dangling effect target {}",
                effect.index()
            )))
        }
        AnnotationTargetFact::Call(_) | AnnotationTargetFact::Effect(_) => Ok(()),
    }
}

fn validate_macro_expansions(
    frames: &[MacroExpansionFact],
    source_lengths: &BTreeMap<&SourceFileId, u64>,
) -> Result<(), ArtifactValidationError> {
    for frame in frames {
        require_nonempty(&frame.display_path, "macro display path")?;
        validate_optional_range(frame.source_range.as_ref(), source_lengths)?;
    }
    Ok(())
}

fn validate_attributes(attributes: &FunctionAttributesFact) -> Result<(), ArtifactValidationError> {
    validate_nonempty_sorted_set(&attributes.namespace_candidates, "namespace candidates")?;
    for candidate in &attributes.namespace_candidates {
        require_nonempty(candidate, "namespace candidate")?;
    }
    Ok(())
}

fn validate_call_target(
    target: &CallTargetFact,
    source_lengths: &BTreeMap<&SourceFileId, u64>,
) -> Result<(), ArtifactValidationError> {
    match target {
        CallTargetFact::Function(target) => validate_function_target(target, source_lengths),
        CallTargetFact::OpaqueBoundary {
            description,
            target,
        } => {
            require_nonempty(description, "opaque boundary description")?;
            if let Some(target) = target {
                match target {
                    OpaqueTargetFact::Trait(target) | OpaqueTargetFact::Function(target) => {
                        validate_function_target(target, source_lengths)?;
                    }
                }
            }
            Ok(())
        }
    }
}

fn validate_function_target(
    target: &FunctionTargetFact,
    source_lengths: &BTreeMap<&SourceFileId, u64>,
) -> Result<(), ArtifactValidationError> {
    require_nonempty(&target.display_path, "function target display path")?;
    validate_attributes(&target.attributes)?;
    if let Some(contract) = &target.contracts.panic {
        validate_contract(contract, source_lengths)?;
    }
    if let Some(contract) = &target.contracts.safety {
        validate_contract(contract, source_lengths)?;
    }
    Ok(())
}

fn validate_contract(
    contract: &ContractFact,
    source_lengths: &BTreeMap<&SourceFileId, u64>,
) -> Result<(), ArtifactValidationError> {
    validate_optional_range(contract.source_range.as_ref(), source_lengths)?;
    validate_requirements(&contract.requirements, source_lengths)
}

fn validate_requirements(
    requirements: &[ContractRequirementFact],
    source_lengths: &BTreeMap<&SourceFileId, u64>,
) -> Result<(), ArtifactValidationError> {
    for requirement in requirements {
        if requirement.name.is_empty() {
            require_nonempty(&requirement.condition, "unnamed contract requirement")?;
            if requirement.structural_path.is_empty() {
                return Err(ArtifactValidationError::new(
                    "unnamed contract requirement has no structural path",
                ));
            }
        }
        validate_optional_range(requirement.source_range.as_ref(), source_lengths)?;
    }
    Ok(())
}

fn validate_marker_target(
    body: &FunctionFact,
    marker: &AnnotationFact,
) -> Result<(), ArtifactValidationError> {
    match marker.target {
        AnnotationTargetFact::Function(function) if function != body.function => {
            Err(ArtifactValidationError::new(format!(
                "marker {} has a dangling function target",
                marker.id.index()
            )))
        }
        AnnotationTargetFact::Call(call)
            if body
                .calls
                .binary_search_by_key(&call, |candidate| candidate.id)
                .is_err() =>
        {
            Err(ArtifactValidationError::new(format!(
                "marker {} has a dangling call target {}",
                marker.id.index(),
                call.index()
            )))
        }
        AnnotationTargetFact::Effect(effect)
            if body
                .effects
                .binary_search_by_key(&effect, |candidate| candidate.id)
                .is_err() =>
        {
            Err(ArtifactValidationError::new(format!(
                "marker {} has a dangling effect target {}",
                marker.id.index(),
                effect.index()
            )))
        }
        AnnotationTargetFact::Function(_)
        | AnnotationTargetFact::Call(_)
        | AnnotationTargetFact::Effect(_) => Ok(()),
    }
}

fn validate_optional_range(
    range: Option<&SourceRangeFact>,
    source_lengths: &BTreeMap<&SourceFileId, u64>,
) -> Result<(), ArtifactValidationError> {
    let Some(range) = range else {
        return Ok(());
    };
    let Some(byte_len) = source_lengths.get(&range.file) else {
        return Err(ArtifactValidationError::new(format!(
            "source range refers to undeclared source file `{}`",
            range.file.as_str()
        )));
    };
    if range.byte_start > range.byte_end {
        return Err(ArtifactValidationError::new(format!(
            "source range {}..{} has its end before its start",
            range.byte_start, range.byte_end
        )));
    }
    if range.byte_end > *byte_len {
        return Err(ArtifactValidationError::new(format!(
            "source range {}..{} is outside source file `{}` with byte length {}",
            range.byte_start,
            range.byte_end,
            range.file.as_str(),
            byte_len
        )));
    }
    Ok(())
}

fn validate_nonempty_sorted_set<T: Ord>(
    values: &[T],
    label: &str,
) -> Result<(), ArtifactValidationError> {
    if values.is_empty() {
        return Err(ArtifactValidationError::new(format!(
            "{label} must not be empty"
        )));
    }
    validate_strictly_sorted(values, label)
}

fn validate_sorted_unique<T, K: Ord>(
    values: &[T],
    key: impl Fn(&T) -> K,
    label: &str,
) -> Result<(), ArtifactValidationError> {
    for pair in values.windows(2) {
        match key(&pair[0]).cmp(&key(&pair[1])) {
            Ordering::Less => {}
            Ordering::Equal => {
                return Err(ArtifactValidationError::new(format!("duplicate {label}")));
            }
            Ordering::Greater => {
                return Err(ArtifactValidationError::new(format!(
                    "{label} values are not in canonical order"
                )));
            }
        }
    }
    Ok(())
}

fn validate_strictly_sorted<T: Ord>(
    values: &[T],
    label: &str,
) -> Result<(), ArtifactValidationError> {
    for pair in values.windows(2) {
        match pair[0].cmp(&pair[1]) {
            Ordering::Less => {}
            Ordering::Equal => {
                return Err(ArtifactValidationError::new(format!("duplicate {label}")));
            }
            Ordering::Greater => {
                return Err(ArtifactValidationError::new(format!(
                    "{label} values are not in canonical order"
                )));
            }
        }
    }
    Ok(())
}

fn require_nonempty(value: &str, label: &str) -> Result<(), ArtifactValidationError> {
    if value.trim().is_empty() {
        Err(ArtifactValidationError::new(format!(
            "{label} must not be empty"
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiler_assert_kinds_have_stable_names() {
        for (kind, serialized, description) in [
            (
                CompilerAssertKind::BoundsCheck,
                "bounds-check",
                "index out of bounds",
            ),
            (
                CompilerAssertKind::Overflow,
                "overflow",
                "arithmetic overflow",
            ),
            (
                CompilerAssertKind::OverflowNegation,
                "overflow-negation",
                "negation overflow",
            ),
            (
                CompilerAssertKind::DivisionByZero,
                "division-by-zero",
                "division by zero",
            ),
            (
                CompilerAssertKind::RemainderByZero,
                "remainder-by-zero",
                "remainder with a zero divisor",
            ),
            (
                CompilerAssertKind::ResumedAfterReturn,
                "resumed-after-return",
                "coroutine resumed after returning",
            ),
            (
                CompilerAssertKind::ResumedAfterPanic,
                "resumed-after-panic",
                "coroutine resumed after panicking",
            ),
            (
                CompilerAssertKind::ResumedAfterDrop,
                "resumed-after-drop",
                "coroutine resumed after being dropped",
            ),
            (
                CompilerAssertKind::MisalignedPointerDereference,
                "misaligned-pointer-dereference",
                "misaligned pointer dereference",
            ),
            (
                CompilerAssertKind::NullPointerDereference,
                "null-pointer-dereference",
                "null pointer dereference",
            ),
            (
                CompilerAssertKind::InvalidEnumConstruction,
                "invalid-enum-construction",
                "invalid enum construction",
            ),
        ] {
            let serialized = format!("\"{serialized}\"");
            assert_eq!(
                serde_json::to_string(&kind).expect("serialize compiler assert kind"),
                serialized
            );
            assert_eq!(
                serde_json::from_str::<CompilerAssertKind>(&serialized)
                    .expect("deserialize compiler assert kind"),
                kind
            );
            assert_eq!(kind.human_description(), description);
        }
    }

    #[test]
    fn safety_op_kinds_have_stable_user_facing_names() {
        let cases = [
            (
                SafetyOpKind::DerefRawPointer,
                "raw-pointer-dereference",
                "raw pointer dereference",
            ),
            (
                SafetyOpKind::UseOfMutableStatic,
                "mutable-static-access",
                "mutable static access",
            ),
            (
                SafetyOpKind::UseOfExternStatic,
                "extern-static-access",
                "extern static access",
            ),
            (
                SafetyOpKind::AccessToUnionField,
                "union-field-access",
                "union field access",
            ),
            (
                SafetyOpKind::UseOfUnsafeField,
                "unsafe-field-access",
                "unsafe field access",
            ),
            (
                SafetyOpKind::InitializingLayoutConstrainedType,
                "layout-constrained-type-initialization",
                "layout-constrained type initialization",
            ),
            (
                SafetyOpKind::InitializingTypeWithUnsafeField,
                "unsafe-field-initialization",
                "unsafe field initialization",
            ),
            (
                SafetyOpKind::MutationOfLayoutConstrainedField,
                "layout-constrained-field-mutation",
                "layout-constrained field mutation",
            ),
            (
                SafetyOpKind::BorrowOfLayoutConstrainedField,
                "layout-constrained-field-borrow",
                "layout-constrained field borrow",
            ),
            (
                SafetyOpKind::InlineAssembly,
                "inline-assembly",
                "inline assembly",
            ),
            (
                SafetyOpKind::UnsafeBinderCast,
                "unsafe-binder-cast",
                "unsafe binder cast",
            ),
        ];

        for (kind, expected, label) in cases {
            let serialized = serde_json::to_string(&kind).expect("serialize safety op kind");
            assert_eq!(serialized, format!("\"{expected}\""));
            assert_eq!(
                serde_json::from_str::<SafetyOpKind>(&serialized).expect("deserialize safety op"),
                kind
            );
            assert_eq!(kind.label(), label);
        }
    }

    fn def_hash(value: &str) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{value}\"")).expect("valid definition hash")
    }

    fn instance_hash(value: &str) -> StableInstanceHash {
        serde_json::from_str(&format!("\"{value}\"")).expect("valid instance hash")
    }

    fn source_file() -> SourceFileFact {
        SourceFileFact {
            id: SourceFileId::new("source-1"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:0123456789abcdef"),
            byte_len: 256,
        }
    }

    fn range(start: u64, end: u64) -> SourceRangeFact {
        SourceRangeFact {
            file: SourceFileId::new("source-1"),
            byte_start: start,
            byte_end: end,
        }
    }

    #[test]
    fn macro_expansion_value_equality_includes_its_display_path() {
        let first = MacroExpansionFact {
            macro_def: def_hash("00000000000000010000000000000002"),
            display_path: String::from("core::ub_checks::assert_unsafe_precondition"),
            source_range: Some(range(10, 20)),
        };
        let mut second = first.clone();
        second.display_path = String::from("polluted::visible::alias");

        assert_ne!(first, second);
        assert!(same_macro_provenance(&[first], &[second]));
    }

    fn attributes() -> FunctionAttributesFact {
        FunctionAttributesFact {
            is_unsafe: false,
            is_exported: true,
            has_rust_body: true,
            is_foreign: false,
            namespace_candidates: vec![
                String::from("sample::root"),
                String::from("sample"),
                String::from("sample::root"),
            ],
        }
    }

    fn empty_body(function: FunctionId, display_path: &str) -> FunctionFact {
        FunctionFact {
            function,
            provenance: FunctionFactProvenance::DefiningArtifact,
            display_path: display_path.to_owned(),
            attributes: attributes(),
            contract_declaration: None,
            source_range: None,
            calls: Vec::new(),
            effects: Vec::new(),
            markers: Vec::new(),
            unverified_marker_probes: Vec::new(),
        }
    }

    #[test]
    fn namespace_candidates_union_every_occurrence_of_a_stable_definition() {
        let shared = FunctionId::generic(def_hash("00000000000000010000000000000002"));
        let root = FunctionId::generic(def_hash("00000000000000030000000000000004"));
        let target = |alias: &str| FunctionTargetFact {
            function: shared,
            display_path: alias.to_owned(),
            attributes: FunctionAttributesFact {
                namespace_candidates: vec![alias.to_owned()],
                ..attributes()
            },
            contracts: FunctionContractsFact::default(),
        };
        let mut shared_body = empty_body(shared, "body::alias");
        shared_body.attributes.namespace_candidates = vec![String::from("body::alias")];
        let mut root_body = empty_body(root, "sample::root");
        root_body.contract_declaration = Some(target("contract::alias"));
        root_body.calls.push(CallFact {
            id: CallId::new(0),
            call_site: CallSiteId::new(0),
            kind: CallKindFact::DirectCall,
            safety_effect_group: Some(SafetyEffectGroupId::new(0)),
            requires_unsafe: false,
            inside_builtin_unsafe: false,
            source_range: None,
            expanded_range: None,
            macro_expansions: Vec::new(),
            callee_range: None,
            indirect_kind: None,
            declaration_target: Some(target("declaration::alias")),
            target: CallTargetFact::Function(target("call::alias")),
        });
        let artifact = ArtifactFacts::new(vec![root_body, shared_body], Vec::new())
            .expect("valid artifact facts");

        assert_eq!(
            artifact.definition_namespace_index().candidates(shared),
            [
                String::from("body::alias"),
                String::from("call::alias"),
                String::from("contract::alias"),
                String::from("declaration::alias"),
            ]
        );
    }

    fn compiler_assert_effect(id: u32) -> EffectFact {
        EffectFact {
            id: EffectId::new(id),
            safety_effect_group: None,
            source_range: None,
            expanded_range: None,
            macro_expansions: Vec::new(),
            kind: EffectFactKind::CompilerAssert {
                kind: CompilerAssertKind::BoundsCheck,
            },
        }
    }

    fn direct_call(id: u32, group: u32, source_range: SourceRangeFact) -> CallFact {
        CallFact {
            id: CallId::new(id),
            call_site: CallSiteId::new(id),
            kind: CallKindFact::DirectCall,
            safety_effect_group: Some(SafetyEffectGroupId::new(group)),
            requires_unsafe: false,
            inside_builtin_unsafe: false,
            source_range: Some(source_range.clone()),
            expanded_range: Some(source_range.clone()),
            macro_expansions: Vec::new(),
            callee_range: Some(source_range),
            indirect_kind: None,
            declaration_target: None,
            target: CallTargetFact::OpaqueBoundary {
                description: String::from("unresolved test call"),
                target: None,
            },
        }
    }

    fn source_less_call(id: u32, group: u32) -> CallFact {
        let mut call = direct_call(id, group, range(0, 1));
        call.source_range = None;
        call.expanded_range = None;
        call.callee_range = None;
        call
    }

    fn source_less_macro_expansion() -> MacroExpansionFact {
        MacroExpansionFact {
            macro_def: def_hash("00000000000000410000000000000042"),
            display_path: String::from("dependency::source_less_macro"),
            source_range: None,
        }
    }

    fn unsafe_effect(id: u32, group: u32, source_range: SourceRangeFact) -> EffectFact {
        EffectFact {
            id: EffectId::new(id),
            safety_effect_group: Some(SafetyEffectGroupId::new(group)),
            source_range: Some(source_range.clone()),
            expanded_range: Some(source_range),
            macro_expansions: Vec::new(),
            kind: EffectFactKind::UnsafeOperation {
                kind: SafetyOpKind::DerefRawPointer,
            },
        }
    }

    fn source_less_unsafe_effect(id: u32, group: u32) -> EffectFact {
        let mut effect = unsafe_effect(id, group, range(0, 1));
        effect.source_range = None;
        effect.expanded_range = None;
        effect
    }

    fn marker_probe_body(function: FunctionId, display_path: &str) -> FunctionFact {
        let mut body = empty_body(function, display_path);
        body.effects = vec![compiler_assert_effect(0), compiler_assert_effect(1)];
        body.markers.push(AnnotationFact {
            id: MarkerId::new(0),
            identity: String::from("panic-marker"),
            kind: AnnotationFactKind::PanicJustification,
            source_range: None,
            target: AnnotationTargetFact::Effect(EffectId::new(0)),
            applicable_probing: vec![AnnotationProbingFact::SourceCallsite],
            satisfactions: vec![AnnotationSatisfactionFact {
                requirement: None,
                reason: String::from("checked immediately above"),
                structural_path: None,
            }],
            requirements: Vec::new(),
        });
        body.unverified_marker_probes
            .push(UnverifiedMarkerProbeFact {
                kind: AnnotationFactKind::PanicJustification,
                target: AnnotationTargetFact::Effect(EffectId::new(0)),
                probing: AnnotationProbingFact::MacroDefinitionFirst,
                reason: UnverifiedMarkerProbeReason::SourceUnavailable,
            });
        body
    }

    #[test]
    fn marker_evidence_is_three_way_while_the_serialized_gap_facts_stay_sparse() {
        let function = FunctionId::generic(def_hash("00000000000000210000000000000022"));
        let artifact = ArtifactFacts::new(
            vec![marker_probe_body(function, "sample::probe")],
            Vec::new(),
        )
        .expect("valid marker probe facts");
        let body = artifact.function_body(function).expect("probe body");

        assert_eq!(
            body.marker_evidence_state(
                AnnotationFactKind::PanicJustification,
                AnnotationTargetFact::Effect(EffectId::new(0)),
                AnnotationProbingFact::SourceCallsite,
            ),
            Some(MarkerEvidenceState::Present)
        );
        assert_eq!(
            body.marker_evidence_state(
                AnnotationFactKind::PanicJustification,
                AnnotationTargetFact::Effect(EffectId::new(0)),
                AnnotationProbingFact::MacroDefinitionFirst,
            ),
            Some(MarkerEvidenceState::Unverified(
                UnverifiedMarkerProbeReason::SourceUnavailable
            ))
        );
        assert_eq!(
            body.marker_evidence_state(
                AnnotationFactKind::PanicJustification,
                AnnotationTargetFact::Effect(EffectId::new(1)),
                AnnotationProbingFact::SourceCallsite,
            ),
            Some(MarkerEvidenceState::VerifiedAbsent)
        );
        assert_eq!(
            body.marker_evidence_state(
                AnnotationFactKind::SafetyJustification,
                AnnotationTargetFact::Effect(EffectId::new(1)),
                AnnotationProbingFact::SourceCallsite,
            ),
            None,
            "a compiler assertion is not a safety-effect marker probe key"
        );

        let encoded = serde_json::to_string(&artifact).expect("serialize marker probe facts");
        assert_eq!(encoded.matches("unverified-marker-probes").count(), 1);
        assert!(encoded.contains("\"reason\":\"source-unavailable\""));
        let decoded: ArtifactFacts =
            serde_json::from_str(&encoded).expect("deserialize marker probe facts");
        assert_eq!(decoded, artifact);
    }

    #[test]
    fn validation_rejects_present_and_unverified_evidence_for_the_same_probe_key() {
        let function = FunctionId::generic(def_hash("00000000000000210000000000000022"));
        let mut body = marker_probe_body(function, "sample::probe");
        body.unverified_marker_probes[0].probing = AnnotationProbingFact::SourceCallsite;

        let error = ArtifactFacts::new(vec![body], Vec::new())
            .expect_err("one probe key cannot be both present and unverified");

        assert!(error.to_string().contains("both present and unverified"));
    }

    #[test]
    fn validation_rejects_multiple_unverified_reasons_for_the_same_probe_key() {
        let function = FunctionId::generic(def_hash("00000000000000210000000000000022"));
        let mut body = marker_probe_body(function, "sample::probe");
        let mut duplicate = body.unverified_marker_probes[0];
        duplicate.reason = UnverifiedMarkerProbeReason::NoUsableSourceSpan;
        body.unverified_marker_probes.push(duplicate);

        let error = ArtifactFacts::new(vec![body], Vec::new())
            .expect_err("one probe key must have one stable unverified reason");

        assert!(
            error
                .to_string()
                .contains("duplicate unverified marker probe")
        );
    }

    #[test]
    fn source_marker_evidence_prefers_the_defining_body_over_a_consumer_overlay() {
        let definition = def_hash("00000000000000210000000000000022");
        let generic = FunctionId::generic(definition);
        let exact = FunctionId::exact(
            definition,
            instance_hash("00000000000000230000000000000024"),
        );
        let mut defining = marker_probe_body(generic, "dependency::generic");
        defining.effects[0].source_range = Some(range(10, 20));
        defining.effects[0].expanded_range = Some(range(10, 20));
        defining.effects[1].source_range = Some(range(30, 40));
        defining.effects[1].expanded_range = Some(range(30, 40));
        let mut overlay = empty_body(exact, "dependency::generic::<Local>");
        overlay.provenance = FunctionFactProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: 1,
        };
        let mut overlay_effect = compiler_assert_effect(0);
        overlay_effect.source_range = Some(range(10, 20));
        overlay_effect.expanded_range = Some(range(10, 20));
        overlay.effects.push(overlay_effect);
        overlay
            .unverified_marker_probes
            .push(UnverifiedMarkerProbeFact {
                kind: AnnotationFactKind::PanicJustification,
                target: AnnotationTargetFact::Effect(EffectId::new(0)),
                probing: AnnotationProbingFact::SourceCallsite,
                reason: UnverifiedMarkerProbeReason::SourceUnavailable,
            });
        let artifact = ArtifactFacts::new(vec![defining, overlay], vec![source_file()])
            .expect("valid overlay facts");

        assert_eq!(
            artifact.source_marker_evidence_state(
                exact,
                AnnotationFactKind::PanicJustification,
                AnnotationTargetFact::Effect(EffectId::new(0)),
                AnnotationProbingFact::SourceCallsite,
            ),
            Some(MarkerEvidenceState::Present)
        );
    }

    #[test]
    fn source_marker_evidence_falls_back_when_the_defining_body_has_no_matching_key() {
        let definition = def_hash("00000000000000250000000000000026");
        let generic = FunctionId::generic(definition);
        let exact = FunctionId::exact(
            definition,
            instance_hash("00000000000000270000000000000028"),
        );
        let defining = empty_body(generic, "dependency::generic");
        let mut overlay = empty_body(exact, "dependency::generic::<Local>");
        overlay.provenance = FunctionFactProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: 1,
        };
        overlay.effects.push(compiler_assert_effect(0));
        overlay
            .unverified_marker_probes
            .push(UnverifiedMarkerProbeFact {
                kind: AnnotationFactKind::PanicJustification,
                target: AnnotationTargetFact::Effect(EffectId::new(0)),
                probing: AnnotationProbingFact::SourceCallsite,
                reason: UnverifiedMarkerProbeReason::SourceUnavailable,
            });
        let artifact =
            ArtifactFacts::new(vec![defining, overlay], Vec::new()).expect("valid overlay facts");

        assert_eq!(
            artifact.source_marker_evidence_state(
                exact,
                AnnotationFactKind::PanicJustification,
                AnnotationTargetFact::Effect(EffectId::new(0)),
                AnnotationProbingFact::SourceCallsite,
            ),
            Some(MarkerEvidenceState::Unverified(
                UnverifiedMarkerProbeReason::SourceUnavailable
            ))
        );
    }

    #[test]
    fn source_call_marker_evidence_projects_overlay_ids_to_the_defining_site() {
        let definition = def_hash("00000000000000290000000000000030");
        let generic = FunctionId::generic(definition);
        let exact = FunctionId::exact(
            definition,
            instance_hash("00000000000000310000000000000032"),
        );
        let mut defining = empty_body(generic, "dependency::generic");
        defining.calls = vec![
            direct_call(0, 0, range(10, 20)),
            direct_call(1, 1, range(30, 40)),
            direct_call(2, 2, range(30, 40)),
            direct_call(3, 3, range(30, 40)),
        ];
        defining.markers.push(AnnotationFact {
            id: MarkerId::new(0),
            identity: String::from("panic-call-marker"),
            kind: AnnotationFactKind::PanicJustification,
            source_range: Some(range(30, 40)),
            target: AnnotationTargetFact::Call(CallId::new(1)),
            applicable_probing: vec![AnnotationProbingFact::SourceCallsite],
            satisfactions: Vec::new(),
            requirements: Vec::new(),
        });
        defining.unverified_marker_probes.extend([
            UnverifiedMarkerProbeFact {
                kind: AnnotationFactKind::PanicJustification,
                target: AnnotationTargetFact::Call(CallId::new(1)),
                probing: AnnotationProbingFact::MacroDefinitionFirst,
                reason: UnverifiedMarkerProbeReason::NoUsableSourceSpan,
            },
            UnverifiedMarkerProbeFact {
                kind: AnnotationFactKind::PanicJustification,
                target: AnnotationTargetFact::Call(CallId::new(2)),
                probing: AnnotationProbingFact::MacroDefinitionFirst,
                reason: UnverifiedMarkerProbeReason::SourceUnavailable,
            },
        ]);
        let mut overlay = empty_body(exact, "dependency::generic::<Local>");
        overlay.provenance = FunctionFactProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: 1,
        };
        overlay.calls.push(direct_call(0, 0, range(30, 40)));
        let artifact = ArtifactFacts::new(vec![defining, overlay], vec![source_file()])
            .expect("valid call projection facts");

        assert_eq!(
            artifact.source_marker_evidence_state(
                exact,
                AnnotationFactKind::PanicJustification,
                AnnotationTargetFact::Call(CallId::new(0)),
                AnnotationProbingFact::SourceCallsite,
            ),
            Some(MarkerEvidenceState::Present)
        );
        assert_eq!(
            artifact.source_marker_evidence_state(
                exact,
                AnnotationFactKind::PanicJustification,
                AnnotationTargetFact::Call(CallId::new(0)),
                AnnotationProbingFact::MacroDefinitionFirst,
            ),
            Some(MarkerEvidenceState::Unverified(
                UnverifiedMarkerProbeReason::SourceUnavailable
            ))
        );
    }

    #[test]
    fn source_less_calls_do_not_cross_project_marker_evidence() {
        let definition = def_hash("00000000000000370000000000000038");
        let generic = FunctionId::generic(definition);
        let exact = FunctionId::exact(
            definition,
            instance_hash("00000000000000390000000000000040"),
        );
        let mut defining = empty_body(generic, "dependency::generic");
        defining.calls = vec![source_less_call(0, 0), source_less_call(1, 1)];
        defining.markers.push(AnnotationFact {
            id: MarkerId::new(0),
            identity: String::from("unmappable-panic-call-marker"),
            kind: AnnotationFactKind::PanicJustification,
            source_range: None,
            target: AnnotationTargetFact::Call(CallId::new(1)),
            applicable_probing: vec![AnnotationProbingFact::SourceCallsite],
            satisfactions: Vec::new(),
            requirements: Vec::new(),
        });
        let mut overlay = empty_body(exact, "dependency::generic::<Local>");
        overlay.provenance = FunctionFactProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: 1,
        };
        overlay.calls.push(source_less_call(0, 0));
        overlay
            .unverified_marker_probes
            .push(UnverifiedMarkerProbeFact {
                kind: AnnotationFactKind::PanicJustification,
                target: AnnotationTargetFact::Call(CallId::new(0)),
                probing: AnnotationProbingFact::SourceCallsite,
                reason: UnverifiedMarkerProbeReason::SourceUnavailable,
            });
        let artifact = ArtifactFacts::new(vec![defining, overlay], Vec::new())
            .expect("valid source-less call facts");

        assert_eq!(
            artifact.source_marker_evidence_state(
                exact,
                AnnotationFactKind::PanicJustification,
                AnnotationTargetFact::Call(CallId::new(0)),
                AnnotationProbingFact::SourceCallsite,
            ),
            Some(MarkerEvidenceState::Unverified(
                UnverifiedMarkerProbeReason::SourceUnavailable
            ))
        );
    }

    #[test]
    fn source_less_macro_calls_do_not_cross_project_marker_evidence() {
        let definition = def_hash("00000000000000430000000000000044");
        let generic = FunctionId::generic(definition);
        let exact = FunctionId::exact(
            definition,
            instance_hash("00000000000000450000000000000046"),
        );
        let mut defining = empty_body(generic, "dependency::generic");
        defining.calls = vec![source_less_call(0, 0), source_less_call(1, 1)];
        for call in &mut defining.calls {
            call.macro_expansions.push(source_less_macro_expansion());
        }
        defining.markers.push(AnnotationFact {
            id: MarkerId::new(0),
            identity: String::from("unmappable-macro-call-marker"),
            kind: AnnotationFactKind::PanicJustification,
            source_range: None,
            target: AnnotationTargetFact::Call(CallId::new(1)),
            applicable_probing: vec![AnnotationProbingFact::SourceCallsite],
            satisfactions: Vec::new(),
            requirements: Vec::new(),
        });
        let mut overlay = empty_body(exact, "dependency::generic::<Local>");
        overlay.provenance = FunctionFactProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: 1,
        };
        let mut overlay_call = source_less_call(0, 0);
        overlay_call
            .macro_expansions
            .push(source_less_macro_expansion());
        overlay.calls.push(overlay_call);
        overlay
            .unverified_marker_probes
            .push(UnverifiedMarkerProbeFact {
                kind: AnnotationFactKind::PanicJustification,
                target: AnnotationTargetFact::Call(CallId::new(0)),
                probing: AnnotationProbingFact::SourceCallsite,
                reason: UnverifiedMarkerProbeReason::SourceUnavailable,
            });
        let artifact = ArtifactFacts::new(vec![defining, overlay], Vec::new())
            .expect("valid source-less macro call facts");

        assert_eq!(
            artifact.source_marker_evidence_state(
                exact,
                AnnotationFactKind::PanicJustification,
                AnnotationTargetFact::Call(CallId::new(0)),
                AnnotationProbingFact::SourceCallsite,
            ),
            Some(MarkerEvidenceState::Unverified(
                UnverifiedMarkerProbeReason::SourceUnavailable
            ))
        );
    }

    #[test]
    fn source_effect_marker_evidence_projects_overlay_ids_to_the_defining_site() {
        let definition = def_hash("00000000000000330000000000000034");
        let generic = FunctionId::generic(definition);
        let exact = FunctionId::exact(
            definition,
            instance_hash("00000000000000350000000000000036"),
        );
        let mut defining = empty_body(generic, "dependency::generic");
        defining.effects = vec![
            unsafe_effect(0, 0, range(50, 60)),
            unsafe_effect(1, 1, range(70, 80)),
        ];
        defining.markers.push(AnnotationFact {
            id: MarkerId::new(0),
            identity: String::from("safety-effect-marker"),
            kind: AnnotationFactKind::SafetyJustification,
            source_range: Some(range(70, 80)),
            target: AnnotationTargetFact::Effect(EffectId::new(1)),
            applicable_probing: vec![AnnotationProbingFact::SourceCallsite],
            satisfactions: Vec::new(),
            requirements: Vec::new(),
        });
        let mut overlay = empty_body(exact, "dependency::generic::<Local>");
        overlay.provenance = FunctionFactProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: 1,
        };
        overlay.effects.push(unsafe_effect(0, 99, range(70, 80)));
        let artifact = ArtifactFacts::new(vec![defining, overlay], vec![source_file()])
            .expect("valid effect projection facts");

        assert_eq!(
            artifact.source_marker_evidence_state(
                exact,
                AnnotationFactKind::SafetyJustification,
                AnnotationTargetFact::Effect(EffectId::new(0)),
                AnnotationProbingFact::SourceCallsite,
            ),
            Some(MarkerEvidenceState::Present)
        );
    }

    #[test]
    fn source_less_macro_effects_do_not_cross_project_marker_evidence() {
        let definition = def_hash("00000000000000470000000000000048");
        let generic = FunctionId::generic(definition);
        let exact = FunctionId::exact(
            definition,
            instance_hash("00000000000000490000000000000050"),
        );
        let mut defining = empty_body(generic, "dependency::generic");
        let mut defining_effect = source_less_unsafe_effect(1, 1);
        defining_effect
            .macro_expansions
            .push(source_less_macro_expansion());
        defining.effects.push(defining_effect);
        defining.markers.push(AnnotationFact {
            id: MarkerId::new(0),
            identity: String::from("unmappable-macro-effect-marker"),
            kind: AnnotationFactKind::SafetyJustification,
            source_range: None,
            target: AnnotationTargetFact::Effect(EffectId::new(1)),
            applicable_probing: vec![AnnotationProbingFact::SourceCallsite],
            satisfactions: Vec::new(),
            requirements: Vec::new(),
        });
        let mut overlay = empty_body(exact, "dependency::generic::<Local>");
        overlay.provenance = FunctionFactProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: 1,
        };
        let mut overlay_effect = source_less_unsafe_effect(0, 1);
        overlay_effect
            .macro_expansions
            .push(source_less_macro_expansion());
        overlay.effects.push(overlay_effect);
        overlay
            .unverified_marker_probes
            .push(UnverifiedMarkerProbeFact {
                kind: AnnotationFactKind::SafetyJustification,
                target: AnnotationTargetFact::Effect(EffectId::new(0)),
                probing: AnnotationProbingFact::SourceCallsite,
                reason: UnverifiedMarkerProbeReason::SourceUnavailable,
            });
        let artifact = ArtifactFacts::new(vec![defining, overlay], Vec::new())
            .expect("valid source-less macro effect facts");

        assert_eq!(
            artifact.source_marker_evidence_state(
                exact,
                AnnotationFactKind::SafetyJustification,
                AnnotationTargetFact::Effect(EffectId::new(0)),
                AnnotationProbingFact::SourceCallsite,
            ),
            Some(MarkerEvidenceState::Unverified(
                UnverifiedMarkerProbeReason::SourceUnavailable
            ))
        );
    }

    #[test]
    fn function_lookup_prefers_an_exact_consumer_overlay_and_falls_back_to_its_definition() {
        let definition = def_hash("00000000000000010000000000000002");
        let generic = FunctionId::generic(definition);
        let exact = FunctionId::exact(
            definition,
            instance_hash("00000000000000030000000000000004"),
        );
        let missing_exact = FunctionId::exact(
            definition,
            instance_hash("00000000000000050000000000000006"),
        );
        let mut overlay = empty_body(exact, "sample::generic::<Local>");
        overlay.provenance = FunctionFactProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: 1,
        };
        let artifact = ArtifactFacts::new(
            vec![empty_body(generic, "sample::generic"), overlay],
            Vec::new(),
        )
        .expect("valid artifact facts");

        assert_eq!(
            artifact
                .function_body(exact)
                .expect("exact consumer overlay")
                .function,
            exact
        );
        assert_eq!(
            artifact
                .function_body(missing_exact)
                .expect("generic fallback")
                .function,
            generic
        );
        assert_eq!(
            artifact
                .defining_function_body(exact)
                .expect("generic defining body")
                .function,
            generic
        );
    }

    #[test]
    fn defining_function_lookup_keeps_an_exact_definition_without_a_generic_body() {
        let exact = FunctionId::exact(
            def_hash("00000000000000010000000000000002"),
            instance_hash("00000000000000030000000000000004"),
        );
        let missing = FunctionId::generic(def_hash("00000000000000050000000000000006"));
        let artifact = ArtifactFacts::new(vec![empty_body(exact, "sample::closure")], Vec::new())
            .expect("valid artifact facts");

        assert_eq!(
            artifact
                .defining_function_body(exact)
                .expect("exact defining body")
                .function,
            exact
        );
        assert!(artifact.function_body(missing).is_none());
        assert!(artifact.defining_function_body(missing).is_none());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one complete facts fixture makes cross-field round-trip coverage explicit"
    )]
    fn json_round_trip_preserves_raw_analysis_facts_and_ranges() {
        let root = FunctionId::generic(def_hash("00000000000000010000000000000002"));
        let callee = FunctionId::exact(
            def_hash("00000000000000030000000000000004"),
            instance_hash("00000000000000050000000000000006"),
        );
        let callee_target = FunctionTargetFact {
            function: callee,
            display_path: String::from("dependency::callee::<u8>"),
            attributes: FunctionAttributesFact {
                is_unsafe: true,
                is_exported: false,
                has_rust_body: true,
                is_foreign: false,
                namespace_candidates: vec![
                    String::from("dependency::callee"),
                    String::from("dependency"),
                ],
            },
            contracts: FunctionContractsFact {
                panic: Some(ContractFact {
                    source_range: Some(range(160, 180)),
                    requirements: vec![ContractRequirementFact {
                        name: String::from("input-valid"),
                        condition: String::from("the input is valid"),
                        structural_path: vec![0],
                        source_range: Some(range(165, 178)),
                    }],
                }),
                safety: None,
            },
        };
        let declaration_target = FunctionTargetFact {
            function: FunctionId::generic(def_hash("00000000000000110000000000000012")),
            display_path: String::from("dependency::Action::call"),
            attributes: FunctionAttributesFact {
                is_unsafe: true,
                is_exported: true,
                has_rust_body: false,
                is_foreign: false,
                namespace_candidates: vec![
                    String::from("dependency::Action::call"),
                    String::from("dependency"),
                ],
            },
            contracts: FunctionContractsFact {
                panic: None,
                safety: Some(ContractFact {
                    source_range: Some(range(181, 200)),
                    requirements: vec![ContractRequirementFact {
                        name: String::from("source-valid"),
                        condition: String::from("the source-level precondition holds"),
                        structural_path: vec![0],
                        source_range: Some(range(185, 198)),
                    }],
                }),
            },
        };
        let root_contract_requirement = ContractRequirementFact {
            name: String::from("capacity"),
            condition: String::from("the buffer has capacity"),
            structural_path: vec![0],
            source_range: Some(range(8, 24)),
        };
        let body = FunctionFact {
            function: root,
            provenance: FunctionFactProvenance::DefiningArtifact,
            display_path: String::from("sample::root"),
            attributes: attributes(),
            contract_declaration: Some(declaration_target.clone()),
            source_range: Some(range(0, 220)),
            calls: vec![CallFact {
                id: CallId::new(4),
                call_site: CallSiteId::new(4),
                kind: CallKindFact::DirectCall,
                safety_effect_group: Some(SafetyEffectGroupId::new(6)),
                requires_unsafe: true,
                inside_builtin_unsafe: true,
                source_range: Some(range(40, 50)),
                expanded_range: Some(range(80, 105)),
                macro_expansions: vec![
                    MacroExpansionFact {
                        macro_def: def_hash("00000000000000070000000000000008"),
                        display_path: String::from("sample::outer_macro"),
                        source_range: Some(range(40, 50)),
                    },
                    MacroExpansionFact {
                        macro_def: def_hash("0000000000000009000000000000000a"),
                        display_path: String::from("sample::inner_macro"),
                        source_range: Some(range(60, 70)),
                    },
                ],
                callee_range: Some(range(80, 90)),
                indirect_kind: None,
                declaration_target: Some(declaration_target),
                target: CallTargetFact::Function(callee_target),
            }],
            effects: vec![
                EffectFact {
                    id: EffectId::new(9),
                    safety_effect_group: Some(SafetyEffectGroupId::new(6)),
                    source_range: Some(range(110, 115)),
                    expanded_range: Some(range(120, 130)),
                    macro_expansions: vec![MacroExpansionFact {
                        macro_def: def_hash("000000000000000b000000000000000c"),
                        display_path: String::from("sample::unsafe_macro"),
                        source_range: Some(range(110, 115)),
                    }],
                    kind: EffectFactKind::UnsafeOperation {
                        kind: SafetyOpKind::DerefRawPointer,
                    },
                },
                EffectFact {
                    id: EffectId::new(2),
                    safety_effect_group: None,
                    source_range: Some(range(108, 118)),
                    expanded_range: Some(range(108, 118)),
                    macro_expansions: Vec::new(),
                    kind: EffectFactKind::CompilerAssert {
                        kind: CompilerAssertKind::BoundsCheck,
                    },
                },
            ],
            markers: vec![
                AnnotationFact {
                    id: MarkerId::new(8),
                    identity: String::from("safety-marker"),
                    kind: AnnotationFactKind::SafetyJustification,
                    source_range: Some(range(106, 108)),
                    target: AnnotationTargetFact::Effect(EffectId::new(9)),
                    applicable_probing: vec![
                        AnnotationProbingFact::SourceCallsite,
                        AnnotationProbingFact::MacroDefinitionFirst,
                    ],
                    satisfactions: vec![AnnotationSatisfactionFact {
                        requirement: None,
                        reason: String::from("the pointer was validated"),
                        structural_path: None,
                    }],
                    requirements: Vec::new(),
                },
                AnnotationFact {
                    id: MarkerId::new(1),
                    identity: String::from("panic-contract"),
                    kind: AnnotationFactKind::PanicContract,
                    source_range: Some(range(0, 30)),
                    target: AnnotationTargetFact::Function(root),
                    applicable_probing: vec![
                        AnnotationProbingFact::MacroDefinitionFirst,
                        AnnotationProbingFact::SourceCallsite,
                        AnnotationProbingFact::MacroDefinitionFirst,
                    ],
                    satisfactions: Vec::new(),
                    requirements: vec![root_contract_requirement],
                },
                AnnotationFact {
                    id: MarkerId::new(3),
                    identity: String::from("panic-marker"),
                    kind: AnnotationFactKind::PanicJustification,
                    source_range: Some(range(70, 79)),
                    target: AnnotationTargetFact::Call(CallId::new(4)),
                    applicable_probing: vec![AnnotationProbingFact::SourceCallsite],
                    satisfactions: vec![AnnotationSatisfactionFact {
                        requirement: Some(String::from("input-valid")),
                        reason: String::from("validated immediately above"),
                        structural_path: Some(vec![0]),
                    }],
                    requirements: Vec::new(),
                },
            ],
            unverified_marker_probes: Vec::new(),
        };

        let artifact =
            ArtifactFacts::new(vec![body], vec![source_file()]).expect("valid artifact facts");
        let encoded = serde_json::to_string_pretty(&artifact).expect("serialize artifact facts");
        let decoded: ArtifactFacts =
            serde_json::from_str(&encoded).expect("deserialize artifact facts");

        assert_eq!(decoded, artifact);
        decoded
            .validate()
            .expect("round-tripped facts remains valid");
        assert_eq!(
            decoded.functions[0].attributes.namespace_candidates,
            ["sample", "sample::root"]
        );
        assert!(decoded.functions[0].calls[0].requires_unsafe);
        assert!(decoded.functions[0].calls[0].inside_builtin_unsafe);
        assert_eq!(
            decoded.functions[0].calls[0].safety_effect_group,
            Some(SafetyEffectGroupId::new(6))
        );
        let declaration_target = decoded.functions[0].calls[0]
            .declaration_target
            .as_ref()
            .expect("round trip preserves the source-level callee");
        assert_eq!(
            declaration_target.function,
            FunctionId::generic(def_hash("00000000000000110000000000000012"))
        );
        assert_eq!(
            declaration_target.attributes.namespace_candidates,
            ["dependency", "dependency::Action::call"]
        );
        assert_eq!(
            declaration_target
                .contracts
                .safety
                .as_ref()
                .expect("source safety contract")
                .requirements[0]
                .name,
            "source-valid"
        );
        assert_eq!(
            decoded.functions[0].markers[0].applicable_probing,
            [
                AnnotationProbingFact::SourceCallsite,
                AnnotationProbingFact::MacroDefinitionFirst
            ]
        );
        assert_eq!(
            decoded.functions[0].effects[0].expanded_range,
            Some(range(108, 118))
        );
        assert_eq!(
            decoded.functions[0].calls[0]
                .macro_expansions
                .iter()
                .map(|frame| frame.display_path.as_str())
                .collect::<Vec<_>>(),
            ["sample::outer_macro", "sample::inner_macro"]
        );
        assert_eq!(
            decoded.functions[0].effects[1].source_range,
            Some(range(110, 115))
        );
        assert_eq!(
            decoded.functions[0].effects[1].safety_effect_group,
            Some(SafetyEffectGroupId::new(6))
        );
        assert_eq!(
            decoded.functions[0].markers[2].source_range,
            Some(range(106, 108))
        );
    }

    #[test]
    fn every_persisted_edge_kind_round_trips() {
        let kinds = [
            CallKindFact::DirectCall,
            CallKindFact::TailCall,
            CallKindFact::MacroExpansion,
            CallKindFact::ConstBody,
            CallKindFact::CoroutineBody,
            CallKindFact::Assert,
            CallKindFact::IndirectCall,
        ];

        let encoded = serde_json::to_string(&kinds).expect("serialize edge kinds");
        let decoded: Vec<CallKindFact> =
            serde_json::from_str(&encoded).expect("deserialize edge kinds");

        assert_eq!(decoded, kinds);
    }

    #[test]
    fn new_rejects_invalid_facts() {
        let function = FunctionId::generic(def_hash("00000000000000010000000000000002"));
        let error = ArtifactFacts::new(
            vec![
                empty_body(function, "sample::first"),
                empty_body(function, "sample::second"),
            ],
            Vec::new(),
        )
        .expect_err("duplicate function identities must be rejected");

        assert!(error.to_string().contains("duplicate function identity"));
    }
}
