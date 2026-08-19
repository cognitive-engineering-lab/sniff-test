use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

pub(crate) use crate::namespace::{StableDefPathHash, StableInstanceHash, StableTypeHash};
pub(crate) use crate::panics::CompilerAssertKind;
pub(crate) use crate::safety::SafetyOpKind;

/// Policy-neutral facts extracted from one rustc artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ArtifactAnalysisIr {
    pub(crate) functions: Vec<FunctionBodyIr>,
    pub(crate) source_files: Vec<SourceFileIr>,
}

impl ArtifactAnalysisIr {
    /// Builds validated IR in its deterministic serialized order.
    pub(crate) fn new(
        functions: Vec<FunctionBodyIr>,
        source_files: Vec<SourceFileIr>,
    ) -> Result<Self, IrValidationError> {
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
            body.calls.sort_by_key(|call| call.id);
            body.effects.sort_by_key(|effect| effect.id);
            body.markers.sort_by_key(|marker| marker.id);

            for call in &mut body.calls {
                sort_and_deduplicate(&mut call.applicable_attribution);
                sort_and_deduplicate(&mut call.callable_keys);
                if let Some(target) = &mut call.source_target {
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
    pub(crate) fn validate(&self) -> Result<(), IrValidationError> {
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
    #[cfg(test)]
    pub(crate) fn function_body(&self, function: FunctionId) -> Option<&FunctionBodyIr> {
        self.function_body_matching(function, |_| true)
    }

    /// Resolves only facts extracted by the function's defining artifact.
    ///
    /// A consumer-instantiation overlay takes precedence for ordinary lookup,
    /// but does not hide a generic defining body from this lookup.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn defining_function_body(&self, function: FunctionId) -> Option<&FunctionBodyIr> {
        self.function_body_matching(function, |body| {
            matches!(body.provenance, FunctionBodyProvenanceIr::DefiningArtifact)
        })
    }

    /// Resolves source-level facts from the defining artifact.
    ///
    /// Nested closures, coroutines, and inline constants can be emitted only
    /// as exact instances. A consumer can assign the same stable definition a
    /// different instance hash, so source facts fall back by definition path
    /// after exact and generic lookup fail.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn defining_source_function_body(
        &self,
        function: FunctionId,
    ) -> Option<&FunctionBodyIr> {
        self.defining_function_body(function).or_else(|| {
            self.functions.iter().find(|body| {
                body.function.def_path_hash == function.def_path_hash
                    && matches!(body.provenance, FunctionBodyProvenanceIr::DefiningArtifact)
            })
        })
    }

    #[cfg(test)]
    fn function_body_matching(
        &self,
        function: FunctionId,
        predicate: impl Fn(&FunctionBodyIr) -> bool,
    ) -> Option<&FunctionBodyIr> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IrValidationError {
    message: String,
}

impl IrValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for IrValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for IrValidationError {}

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
pub(crate) struct FunctionBodyIr {
    pub(crate) function: FunctionId,
    /// Why this artifact owns the serialized body facts.
    pub(crate) provenance: FunctionBodyProvenanceIr,
    pub(crate) display_path: String,
    pub(crate) attributes: FunctionAttributesIr,
    pub(crate) source_range: Option<SourceRangeIr>,
    pub(crate) calls: Vec<CallEdgeIr>,
    pub(crate) effects: Vec<EffectFactIr>,
    pub(crate) markers: Vec<MarkerIr>,
}

/// Provenance for one body in an artifact IR.
///
/// Most bodies are definitions owned by the artifact's crate. A consumer
/// overlay instead records rustc's exact monomorphized view of a definition
/// from another crate, including dispatch choices that can depend on types and
/// impls from the consuming crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub(crate) enum FunctionBodyProvenanceIr {
    DefiningArtifact,
    ConsumerInstantiation { consumer_stable_crate_id: u64 },
}

/// Function metadata needed for root selection and policy interpretation.
#[allow(
    clippy::struct_excessive_bools,
    reason = "these independent compiler facts are serialized IR fields, not mutually exclusive state"
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct FunctionAttributesIr {
    pub(crate) is_unsafe: bool,
    pub(crate) is_exported: bool,
    /// Whether the definition provides a Rust body that an owning artifact IR
    /// is expected to contain. Required trait methods and foreign
    /// declarations are intentional graph boundaries.
    pub(crate) has_rust_body: bool,
    /// The declaration belongs to the current crate but has no Rust body.
    ///
    /// Foreign calls remain policy-neutral call facts. They may still require
    /// a safety justification or match an explicit panic boundary policy, but
    /// absence of a Rust MIR body is intentional rather than incomplete IR.
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
pub(crate) struct SourceFileIr {
    pub(crate) id: SourceFileId,
    pub(crate) filename: String,
    pub(crate) content_hash: String,
    pub(crate) byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct SourceRangeIr {
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
local_index!(SafetyEffectGroupId);

/// One graph edge emitted while expanding a function body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct CallEdgeIr {
    pub(crate) id: CallId,
    /// Artifact-local identity of the source call occurrence. An indirect call
    /// and each concrete callable endpoint derived from it share this value.
    pub(crate) call_site: CallSiteId,
    pub(crate) kind: CallEdgeKindIr,
    /// Artifact-local identity of the source-level THIR unsafe scope (or
    /// standalone call site) that owns this potential safety effect.
    pub(crate) safety_effect_group: Option<SafetyEffectGroupId>,
    /// Whether invoking this call target requires an unsafe context.
    ///
    /// This remains explicit even for opaque function-pointer calls, where no
    /// concrete [`FunctionTargetIr`] exists to carry the function signature.
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
    pub(crate) source_range: Option<SourceRangeIr>,
    /// The semantic call location after macro expansion. This remains
    /// separate from presentation provenance so exact call reconciliation is
    /// stable across workspace and dependency artifacts.
    pub(crate) expanded_range: Option<SourceRangeIr>,
    /// Ordered outermost-to-innermost macro expansions that produced this
    /// semantic call.
    pub(crate) macro_expansions: Vec<MacroExpansionFrameIr>,
    pub(crate) callee_range: Option<SourceRangeIr>,
    pub(crate) applicable_attribution: Vec<CallableAttributionIr>,
    /// Stable erased-callable identities observed on this raw compiler edge.
    ///
    /// Erasure edges associate these keys with a concrete target. Indirect and
    /// dyn-dispatch call edges associate the same keys with an invocation site.
    /// Workspace interpretation joins only evidence reachable from its selected
    /// roots, so cached IR never bakes a report-root-specific target edge.
    pub(crate) callable_keys: Vec<CallableKeyIr>,
    /// Source-contract callee retained from THIR when every matched raw call
    /// fact agrees on one definition.
    ///
    /// Unresolved generic or dynamic dispatch retains the trait declaration
    /// even when a consumer later resolves [`Self::target`] to an impl. Calls
    /// whose impl is already statically selected omit this field, leaving the
    /// runtime target authoritative. This metadata never changes traversal.
    pub(crate) source_target: Option<FunctionTargetIr>,
    pub(crate) target: CallTargetIr,
}

/// One macro definition and source invocation on the path to a semantic fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct MacroExpansionFrameIr {
    pub(crate) macro_def: StableDefPathHash,
    pub(crate) display_path: String,
    pub(crate) source_range: Option<SourceRangeIr>,
}

/// Serialized mirror of every `reachability::ReachabilityEdgeKind` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CallEdgeKindIr {
    DirectCall,
    TailCall,
    FnPointerReify,
    ClosureFnPointerReify,
    FnPointerCallTarget,
    DynObjectCast,
    VTableEntry,
    DynDispatchVTableEntry,
    MacroExpansion,
    ConstBody,
    CoroutineBody,
    Assert,
    IndirectCall,
}

/// Callable-attribution modes in which an extracted edge applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CallableAttributionIr {
    ErasureSites,
    CallSites,
}

/// Stable key used to join a callable erasure with matching invocation sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "identity")]
pub(crate) enum CallableKeyIr {
    FnPointer(StableTypeHash),
    DynDispatch(StableDefPathHash),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "target")]
pub(crate) enum CallTargetIr {
    Function(FunctionTargetIr),
    OpaqueBoundary {
        description: String,
        target: Option<OpaqueTargetIr>,
    },
}

/// Optional stable identity retained for an otherwise opaque boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "target")]
pub(crate) enum OpaqueTargetIr {
    Trait(FunctionTargetIr),
    Function(FunctionTargetIr),
}

/// Stable callee metadata sufficient for policy interpretation without a body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct FunctionTargetIr {
    pub(crate) function: FunctionId,
    pub(crate) display_path: String,
    pub(crate) attributes: FunctionAttributesIr,
    pub(crate) contracts: FunctionContractsIr,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct FunctionContractsIr {
    pub(crate) panic: Option<RawContractIr>,
    pub(crate) safety: Option<RawContractIr>,
}

/// Raw documented contract, before any requirement satisfaction is interpreted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct RawContractIr {
    pub(crate) source_range: Option<SourceRangeIr>,
    pub(crate) requirements: Vec<ContractRequirementIr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ContractRequirementIr {
    pub(crate) name: String,
    pub(crate) condition: String,
    pub(crate) source_range: Option<SourceRangeIr>,
}

/// One raw effect site in a function body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct EffectFactIr {
    pub(crate) id: EffectId,
    /// Present exactly for safety effects, where multiple runtime operations
    /// can belong to one source-level unsafe scope.
    pub(crate) safety_effect_group: Option<SafetyEffectGroupId>,
    /// Preferred presentation location, normally the outermost macro
    /// invocation when the effect was expanded from a macro.
    pub(crate) source_range: Option<SourceRangeIr>,
    /// The semantic effect location after macro expansion.
    pub(crate) expanded_range: Option<SourceRangeIr>,
    /// Ordered outermost-to-innermost macro expansions that produced the
    /// semantic effect.
    pub(crate) macro_expansions: Vec<MacroExpansionFrameIr>,
    pub(crate) kind: EffectKindIr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "effect")]
pub(crate) enum EffectKindIr {
    CompilerAssert { kind: CompilerAssertKind },
    UnsafeOperation { kind: SafetyOpKind },
}

/// One source marker and the fact it was associated with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct MarkerIr {
    pub(crate) id: MarkerId,
    /// Identity of one logical marker occurrence. A marker in a macro
    /// definition has a distinct identity for each expansion, while the same
    /// occurrence attached to generic and concrete callable edges shares it.
    pub(crate) identity: String,
    pub(crate) kind: MarkerKindIr,
    pub(crate) source_range: Option<SourceRangeIr>,
    pub(crate) target: MarkerTargetIr,
    pub(crate) applicable_probing: Vec<MarkerProbingIr>,
    pub(crate) satisfactions: Vec<MarkerSatisfactionIr>,
    pub(crate) requirements: Vec<ContractRequirementIr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum MarkerKindIr {
    PanicJustification,
    SafetyJustification,
    PanicContract,
    SafetyContract,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "target")]
pub(crate) enum MarkerTargetIr {
    Function(FunctionId),
    Call(CallId),
    Effect(EffectId),
}

/// Marker-probing strategies in which an extracted association applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum MarkerProbingIr {
    SourceCallsite,
    MacroDefinitionFirst,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct MarkerSatisfactionIr {
    pub(crate) requirement: Option<String>,
    pub(crate) reason: String,
}

fn canonicalize_attributes(attributes: &mut FunctionAttributesIr) {
    sort_and_deduplicate(&mut attributes.namespace_candidates);
}

fn canonicalize_call_target(target: &mut CallTargetIr) {
    match target {
        CallTargetIr::Function(target) => canonicalize_function_target(target),
        CallTargetIr::OpaqueBoundary {
            target: Some(target),
            ..
        } => match target {
            OpaqueTargetIr::Trait(target) | OpaqueTargetIr::Function(target) => {
                canonicalize_function_target(target);
            }
        },
        CallTargetIr::OpaqueBoundary { target: None, .. } => {}
    }
}

fn canonicalize_function_target(target: &mut FunctionTargetIr) {
    canonicalize_attributes(&mut target.attributes);
}

fn sort_and_deduplicate<T: Ord>(values: &mut Vec<T>) {
    values.sort();
    values.dedup();
}

fn validate_body(
    body: &FunctionBodyIr,
    source_lengths: &BTreeMap<&SourceFileId, u64>,
) -> Result<(), IrValidationError> {
    require_nonempty(&body.display_path, "function display path")?;
    if matches!(
        body.provenance,
        FunctionBodyProvenanceIr::ConsumerInstantiation { .. }
    ) && body.function.instance_hash.is_none()
    {
        return Err(IrValidationError::new(
            "consumer-instantiation overlay must have an exact function identity",
        ));
    }
    validate_attributes(&body.attributes)?;
    if !body.attributes.has_rust_body {
        return Err(IrValidationError::new(
            "function body is marked as a bodyless declaration",
        ));
    }
    validate_optional_range(body.source_range.as_ref(), source_lengths)?;

    validate_sorted_unique(&body.calls, |call| call.id, "call ID")?;
    for call in &body.calls {
        if call.safety_effect_group.is_none() {
            return Err(IrValidationError::new(format!(
                "call {} has no safety effect group",
                call.id.index()
            )));
        }
        validate_optional_range(call.source_range.as_ref(), source_lengths)?;
        validate_optional_range(call.expanded_range.as_ref(), source_lengths)?;
        validate_macro_expansions(&call.macro_expansions, source_lengths)?;
        validate_optional_range(call.callee_range.as_ref(), source_lengths)?;
        validate_nonempty_sorted_set(
            &call.applicable_attribution,
            "callable-attribution applicability",
        )?;
        validate_strictly_sorted(&call.callable_keys, "callable key")?;
        if let Some(target) = &call.source_target {
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
            EffectKindIr::CompilerAssert { .. } => {
                if effect.safety_effect_group.is_some() {
                    return Err(IrValidationError::new(format!(
                        "compiler assertion effect {} has a safety effect group",
                        effect.id.index()
                    )));
                }
            }
            EffectKindIr::UnsafeOperation { .. } if effect.safety_effect_group.is_none() => {
                return Err(IrValidationError::new(format!(
                    "unsafe operation effect {} has no safety effect group",
                    effect.id.index()
                )));
            }
            EffectKindIr::UnsafeOperation { .. } => {}
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
        }
        validate_requirements(&marker.requirements, source_lengths)?;
    }

    Ok(())
}

fn validate_macro_expansions(
    frames: &[MacroExpansionFrameIr],
    source_lengths: &BTreeMap<&SourceFileId, u64>,
) -> Result<(), IrValidationError> {
    for frame in frames {
        require_nonempty(&frame.display_path, "macro display path")?;
        validate_optional_range(frame.source_range.as_ref(), source_lengths)?;
    }
    Ok(())
}

fn validate_attributes(attributes: &FunctionAttributesIr) -> Result<(), IrValidationError> {
    validate_nonempty_sorted_set(&attributes.namespace_candidates, "namespace candidates")?;
    for candidate in &attributes.namespace_candidates {
        require_nonempty(candidate, "namespace candidate")?;
    }
    Ok(())
}

fn validate_call_target(
    target: &CallTargetIr,
    source_lengths: &BTreeMap<&SourceFileId, u64>,
) -> Result<(), IrValidationError> {
    match target {
        CallTargetIr::Function(target) => validate_function_target(target, source_lengths),
        CallTargetIr::OpaqueBoundary {
            description,
            target,
        } => {
            require_nonempty(description, "opaque boundary description")?;
            if let Some(target) = target {
                match target {
                    OpaqueTargetIr::Trait(target) | OpaqueTargetIr::Function(target) => {
                        validate_function_target(target, source_lengths)?;
                    }
                }
            }
            Ok(())
        }
    }
}

fn validate_function_target(
    target: &FunctionTargetIr,
    source_lengths: &BTreeMap<&SourceFileId, u64>,
) -> Result<(), IrValidationError> {
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
    contract: &RawContractIr,
    source_lengths: &BTreeMap<&SourceFileId, u64>,
) -> Result<(), IrValidationError> {
    validate_optional_range(contract.source_range.as_ref(), source_lengths)?;
    validate_requirements(&contract.requirements, source_lengths)
}

fn validate_requirements(
    requirements: &[ContractRequirementIr],
    source_lengths: &BTreeMap<&SourceFileId, u64>,
) -> Result<(), IrValidationError> {
    for requirement in requirements {
        require_nonempty(&requirement.name, "contract requirement name")?;
        validate_optional_range(requirement.source_range.as_ref(), source_lengths)?;
    }
    Ok(())
}

fn validate_marker_target(
    body: &FunctionBodyIr,
    marker: &MarkerIr,
) -> Result<(), IrValidationError> {
    match marker.target {
        MarkerTargetIr::Function(function) if function != body.function => {
            Err(IrValidationError::new(format!(
                "marker {} has a dangling function target",
                marker.id.index()
            )))
        }
        MarkerTargetIr::Call(call)
            if body
                .calls
                .binary_search_by_key(&call, |candidate| candidate.id)
                .is_err() =>
        {
            Err(IrValidationError::new(format!(
                "marker {} has a dangling call target {}",
                marker.id.index(),
                call.index()
            )))
        }
        MarkerTargetIr::Effect(effect)
            if body
                .effects
                .binary_search_by_key(&effect, |candidate| candidate.id)
                .is_err() =>
        {
            Err(IrValidationError::new(format!(
                "marker {} has a dangling effect target {}",
                marker.id.index(),
                effect.index()
            )))
        }
        MarkerTargetIr::Function(_) | MarkerTargetIr::Call(_) | MarkerTargetIr::Effect(_) => Ok(()),
    }
}

fn validate_optional_range(
    range: Option<&SourceRangeIr>,
    source_lengths: &BTreeMap<&SourceFileId, u64>,
) -> Result<(), IrValidationError> {
    let Some(range) = range else {
        return Ok(());
    };
    let Some(byte_len) = source_lengths.get(&range.file) else {
        return Err(IrValidationError::new(format!(
            "source range refers to undeclared source file `{}`",
            range.file.as_str()
        )));
    };
    if range.byte_start > range.byte_end {
        return Err(IrValidationError::new(format!(
            "source range {}..{} has its end before its start",
            range.byte_start, range.byte_end
        )));
    }
    if range.byte_end > *byte_len {
        return Err(IrValidationError::new(format!(
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
) -> Result<(), IrValidationError> {
    if values.is_empty() {
        return Err(IrValidationError::new(format!("{label} must not be empty")));
    }
    validate_strictly_sorted(values, label)
}

fn validate_sorted_unique<T, K: Ord>(
    values: &[T],
    key: impl Fn(&T) -> K,
    label: &str,
) -> Result<(), IrValidationError> {
    for pair in values.windows(2) {
        match key(&pair[0]).cmp(&key(&pair[1])) {
            Ordering::Less => {}
            Ordering::Equal => {
                return Err(IrValidationError::new(format!("duplicate {label}")));
            }
            Ordering::Greater => {
                return Err(IrValidationError::new(format!(
                    "{label} values are not in canonical order"
                )));
            }
        }
    }
    Ok(())
}

fn validate_strictly_sorted<T: Ord>(values: &[T], label: &str) -> Result<(), IrValidationError> {
    for pair in values.windows(2) {
        match pair[0].cmp(&pair[1]) {
            Ordering::Less => {}
            Ordering::Equal => return Err(IrValidationError::new(format!("duplicate {label}"))),
            Ordering::Greater => {
                return Err(IrValidationError::new(format!(
                    "{label} values are not in canonical order"
                )));
            }
        }
    }
    Ok(())
}

fn require_nonempty(value: &str, label: &str) -> Result<(), IrValidationError> {
    if value.trim().is_empty() {
        Err(IrValidationError::new(format!("{label} must not be empty")))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def_hash(value: &str) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{value}\"")).expect("valid definition hash")
    }

    fn instance_hash(value: &str) -> StableInstanceHash {
        serde_json::from_str(&format!("\"{value}\"")).expect("valid instance hash")
    }

    fn type_hash(value: &str) -> StableTypeHash {
        serde_json::from_str(&format!("\"{value}\"")).expect("valid type hash")
    }

    fn source_file() -> SourceFileIr {
        SourceFileIr {
            id: SourceFileId::new("source-1"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("sha256:0123456789abcdef"),
            byte_len: 256,
        }
    }

    fn range(start: u64, end: u64) -> SourceRangeIr {
        SourceRangeIr {
            file: SourceFileId::new("source-1"),
            byte_start: start,
            byte_end: end,
        }
    }

    fn attributes() -> FunctionAttributesIr {
        FunctionAttributesIr {
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

    fn empty_body(function: FunctionId, display_path: &str) -> FunctionBodyIr {
        FunctionBodyIr {
            function,
            provenance: FunctionBodyProvenanceIr::DefiningArtifact,
            display_path: display_path.to_owned(),
            attributes: attributes(),
            source_range: None,
            calls: Vec::new(),
            effects: Vec::new(),
            markers: Vec::new(),
        }
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
        overlay.provenance = FunctionBodyProvenanceIr::ConsumerInstantiation {
            consumer_stable_crate_id: 1,
        };
        let artifact = ArtifactAnalysisIr::new(
            vec![empty_body(generic, "sample::generic"), overlay],
            Vec::new(),
        )
        .expect("valid artifact IR");

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
        let artifact =
            ArtifactAnalysisIr::new(vec![empty_body(exact, "sample::closure")], Vec::new())
                .expect("valid artifact IR");

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
        reason = "one complete IR fixture makes cross-field round-trip coverage explicit"
    )]
    fn json_round_trip_preserves_raw_analysis_facts_and_ranges() {
        let root = FunctionId::generic(def_hash("00000000000000010000000000000002"));
        let callee = FunctionId::exact(
            def_hash("00000000000000030000000000000004"),
            instance_hash("00000000000000050000000000000006"),
        );
        let callee_target = FunctionTargetIr {
            function: callee,
            display_path: String::from("dependency::callee::<u8>"),
            attributes: FunctionAttributesIr {
                is_unsafe: true,
                is_exported: false,
                has_rust_body: true,
                is_foreign: false,
                namespace_candidates: vec![
                    String::from("dependency::callee"),
                    String::from("dependency"),
                ],
            },
            contracts: FunctionContractsIr {
                panic: Some(RawContractIr {
                    source_range: Some(range(160, 180)),
                    requirements: vec![ContractRequirementIr {
                        name: String::from("input-valid"),
                        condition: String::from("the input is valid"),
                        source_range: Some(range(165, 178)),
                    }],
                }),
                safety: None,
            },
        };
        let source_target = FunctionTargetIr {
            function: FunctionId::generic(def_hash("00000000000000110000000000000012")),
            display_path: String::from("dependency::Action::call"),
            attributes: FunctionAttributesIr {
                is_unsafe: true,
                is_exported: true,
                has_rust_body: false,
                is_foreign: false,
                namespace_candidates: vec![
                    String::from("dependency::Action::call"),
                    String::from("dependency"),
                ],
            },
            contracts: FunctionContractsIr {
                panic: None,
                safety: Some(RawContractIr {
                    source_range: Some(range(181, 200)),
                    requirements: vec![ContractRequirementIr {
                        name: String::from("source-valid"),
                        condition: String::from("the source-level precondition holds"),
                        source_range: Some(range(185, 198)),
                    }],
                }),
            },
        };
        let root_contract_requirement = ContractRequirementIr {
            name: String::from("capacity"),
            condition: String::from("the buffer has capacity"),
            source_range: Some(range(8, 24)),
        };
        let body = FunctionBodyIr {
            function: root,
            provenance: FunctionBodyProvenanceIr::DefiningArtifact,
            display_path: String::from("sample::root"),
            attributes: attributes(),
            source_range: Some(range(0, 220)),
            calls: vec![CallEdgeIr {
                id: CallId::new(4),
                call_site: CallSiteId::new(4),
                kind: CallEdgeKindIr::FnPointerCallTarget,
                safety_effect_group: Some(SafetyEffectGroupId::new(6)),
                requires_unsafe: true,
                inside_builtin_unsafe: true,
                source_range: Some(range(40, 50)),
                expanded_range: Some(range(80, 105)),
                macro_expansions: vec![
                    MacroExpansionFrameIr {
                        macro_def: def_hash("00000000000000070000000000000008"),
                        display_path: String::from("sample::outer_macro"),
                        source_range: Some(range(40, 50)),
                    },
                    MacroExpansionFrameIr {
                        macro_def: def_hash("0000000000000009000000000000000a"),
                        display_path: String::from("sample::inner_macro"),
                        source_range: Some(range(60, 70)),
                    },
                ],
                callee_range: Some(range(80, 90)),
                applicable_attribution: vec![
                    CallableAttributionIr::CallSites,
                    CallableAttributionIr::ErasureSites,
                    CallableAttributionIr::CallSites,
                ],
                callable_keys: vec![
                    CallableKeyIr::FnPointer(type_hash("000000000000000d000000000000000e")),
                    CallableKeyIr::FnPointer(type_hash("000000000000000d000000000000000e")),
                ],
                source_target: Some(source_target),
                target: CallTargetIr::Function(callee_target),
            }],
            effects: vec![
                EffectFactIr {
                    id: EffectId::new(9),
                    safety_effect_group: Some(SafetyEffectGroupId::new(6)),
                    source_range: Some(range(110, 115)),
                    expanded_range: Some(range(120, 130)),
                    macro_expansions: vec![MacroExpansionFrameIr {
                        macro_def: def_hash("000000000000000b000000000000000c"),
                        display_path: String::from("sample::unsafe_macro"),
                        source_range: Some(range(110, 115)),
                    }],
                    kind: EffectKindIr::UnsafeOperation {
                        kind: SafetyOpKind::DerefRawPointer,
                    },
                },
                EffectFactIr {
                    id: EffectId::new(2),
                    safety_effect_group: None,
                    source_range: Some(range(108, 118)),
                    expanded_range: Some(range(108, 118)),
                    macro_expansions: Vec::new(),
                    kind: EffectKindIr::CompilerAssert {
                        kind: CompilerAssertKind::BoundsCheck,
                    },
                },
            ],
            markers: vec![
                MarkerIr {
                    id: MarkerId::new(8),
                    identity: String::from("safety-marker"),
                    kind: MarkerKindIr::SafetyJustification,
                    source_range: Some(range(106, 108)),
                    target: MarkerTargetIr::Effect(EffectId::new(9)),
                    applicable_probing: vec![
                        MarkerProbingIr::SourceCallsite,
                        MarkerProbingIr::MacroDefinitionFirst,
                    ],
                    satisfactions: vec![MarkerSatisfactionIr {
                        requirement: None,
                        reason: String::from("the pointer was validated"),
                    }],
                    requirements: Vec::new(),
                },
                MarkerIr {
                    id: MarkerId::new(1),
                    identity: String::from("panic-contract"),
                    kind: MarkerKindIr::PanicContract,
                    source_range: Some(range(0, 30)),
                    target: MarkerTargetIr::Function(root),
                    applicable_probing: vec![
                        MarkerProbingIr::MacroDefinitionFirst,
                        MarkerProbingIr::SourceCallsite,
                        MarkerProbingIr::MacroDefinitionFirst,
                    ],
                    satisfactions: Vec::new(),
                    requirements: vec![root_contract_requirement],
                },
                MarkerIr {
                    id: MarkerId::new(3),
                    identity: String::from("panic-marker"),
                    kind: MarkerKindIr::PanicJustification,
                    source_range: Some(range(70, 79)),
                    target: MarkerTargetIr::Call(CallId::new(4)),
                    applicable_probing: vec![MarkerProbingIr::SourceCallsite],
                    satisfactions: vec![MarkerSatisfactionIr {
                        requirement: Some(String::from("input-valid")),
                        reason: String::from("validated immediately above"),
                    }],
                    requirements: Vec::new(),
                },
            ],
        };

        let artifact =
            ArtifactAnalysisIr::new(vec![body], vec![source_file()]).expect("valid artifact IR");
        let encoded = serde_json::to_string_pretty(&artifact).expect("serialize artifact IR");
        let decoded: ArtifactAnalysisIr =
            serde_json::from_str(&encoded).expect("deserialize artifact IR");

        assert_eq!(decoded, artifact);
        decoded.validate().expect("round-tripped IR remains valid");
        assert_eq!(
            decoded.functions[0].attributes.namespace_candidates,
            ["sample", "sample::root"]
        );
        assert_eq!(
            decoded.functions[0].calls[0].applicable_attribution,
            [
                CallableAttributionIr::ErasureSites,
                CallableAttributionIr::CallSites
            ]
        );
        assert!(decoded.functions[0].calls[0].requires_unsafe);
        assert!(decoded.functions[0].calls[0].inside_builtin_unsafe);
        assert_eq!(
            decoded.functions[0].calls[0].callable_keys,
            [CallableKeyIr::FnPointer(type_hash(
                "000000000000000d000000000000000e"
            ))]
        );
        assert_eq!(
            decoded.functions[0].calls[0].safety_effect_group,
            Some(SafetyEffectGroupId::new(6))
        );
        let source_target = decoded.functions[0].calls[0]
            .source_target
            .as_ref()
            .expect("round trip preserves the source-level callee");
        assert_eq!(
            source_target.function,
            FunctionId::generic(def_hash("00000000000000110000000000000012"))
        );
        assert_eq!(
            source_target.attributes.namespace_candidates,
            ["dependency", "dependency::Action::call"]
        );
        assert_eq!(
            source_target
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
                MarkerProbingIr::SourceCallsite,
                MarkerProbingIr::MacroDefinitionFirst
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
    fn every_reachability_edge_kind_round_trips() {
        let kinds = [
            CallEdgeKindIr::DirectCall,
            CallEdgeKindIr::TailCall,
            CallEdgeKindIr::FnPointerReify,
            CallEdgeKindIr::ClosureFnPointerReify,
            CallEdgeKindIr::FnPointerCallTarget,
            CallEdgeKindIr::DynObjectCast,
            CallEdgeKindIr::VTableEntry,
            CallEdgeKindIr::DynDispatchVTableEntry,
            CallEdgeKindIr::MacroExpansion,
            CallEdgeKindIr::ConstBody,
            CallEdgeKindIr::CoroutineBody,
            CallEdgeKindIr::Assert,
            CallEdgeKindIr::IndirectCall,
        ];

        let encoded = serde_json::to_string(&kinds).expect("serialize edge kinds");
        let decoded: Vec<CallEdgeKindIr> =
            serde_json::from_str(&encoded).expect("deserialize edge kinds");

        assert_eq!(decoded, kinds);
    }

    #[test]
    fn new_rejects_invalid_ir() {
        let function = FunctionId::generic(def_hash("00000000000000010000000000000002"));
        let error = ArtifactAnalysisIr::new(
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
