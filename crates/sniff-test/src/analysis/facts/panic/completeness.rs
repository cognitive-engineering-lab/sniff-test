//! Typed panic-traversal completeness projection for production authority.
//!
//! This pack owns reached `MissingManagedBody` and `BudgetExceeded` outcomes
//! only. A missing report root still fails
//! `PreparedRootProgramTraversal::prepare` as `UnknownRoot`, before an
//! `EvaluationRoot` or `PanicRootInputs` exists. The production preparation
//! bridge preserves that missing-root case in request order without
//! synthesizing either typed object.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::compiler_assert_inputs::PanicRootInputs;
use super::rules::panic_domain;
use super::trace_route::{TraceRouteEndpoint, TraceRouteSelector};
use crate::analysis::facts::evaluation::{
    EvaluationCx, EvaluationInput, EvaluationIssueContext, EvaluationOutput, EvaluationRule,
    RelationTrace, RuleDescriptor, RuleError, deserialize_strict_relation_trace,
};
use crate::analysis::facts::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::program::root_traversal::{
    ProgramCallResolution, ReconciledCallTargetAuthority, ResolvedBodyVisit,
    ResolvedCallSourceAnchor, ResolvedFollowedCall, ResolvedRootProgramTraversal,
    ResolvedTraversalOutcome, TraversalOutcomeKind,
};
use crate::analysis::facts::program::topology::{
    CallKind, CallMacroExpansionEntity, CallOccurrenceEntity, CallSiteEntity, CallSourceAnchorRole,
    CallTargetRole, CallableEntity,
};
use crate::analysis::facts::program::{
    FunctionEntity, FunctionKey, SourceAnchorEntity, SourceAnchorKey,
};
use crate::analysis::facts::render::{IssueRenderer, RenderCx, RenderedDiagnostic};
use crate::analysis::facts::schema::{DerivedSchema, EntitySchema, IssueSchema, PassId, RowSchema};
use crate::analysis::facts::workspace::{ScopedEntityId, ScopedEntityRef};

pub(super) const EMIT_PANIC_COMPLETENESS_RULE: &str = "sniff-test.panic.emit-completeness";
pub(super) const REPORT_PANIC_INCOMPLETE_RULE: &str = "sniff-test.panic.report-incomplete";

/// Why one panic traversal could not inspect every managed body.
///
/// The variant owns its complete legacy-reason identity. In particular, a
/// node limit has no source or frontier trace because the legacy diagnostic
/// intentionally reports it at the root, while a missing body retains the
/// exact route and presentation anchor that reached it.
#[allow(
    clippy::large_enum_variant,
    reason = "persisted reason variants stay structurally transparent and avoid schema-only boxing"
)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    deny_unknown_fields
)]
pub(crate) enum PanicIncompleteReason {
    MissingManagedBody {
        function: FunctionKey,
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        presentation_source: Option<PanicCompletenessSource>,
        semantic_trace: Vec<PanicCompletenessSemanticStep>,
        #[serde(deserialize_with = "deserialize_strict_relation_trace")]
        relation_trace: RelationTrace,
    },
    NodeLimit {
        limit: u64,
    },
}

impl PanicIncompleteReason {
    #[must_use]
    pub(crate) const fn function(&self) -> Option<FunctionKey> {
        match self {
            Self::MissingManagedBody { function, .. } => Some(*function),
            Self::NodeLimit { .. } => None,
        }
    }

    #[must_use]
    pub(crate) fn path(&self) -> Option<&str> {
        match self {
            Self::MissingManagedBody { path, .. } => Some(path),
            Self::NodeLimit { .. } => None,
        }
    }

    #[must_use]
    pub(crate) const fn presentation_source(&self) -> Option<&PanicCompletenessSource> {
        match self {
            Self::MissingManagedBody {
                presentation_source,
                ..
            } => presentation_source.as_ref(),
            Self::NodeLimit { .. } => None,
        }
    }

    #[must_use]
    pub(crate) fn semantic_trace(&self) -> Option<&[PanicCompletenessSemanticStep]> {
        match self {
            Self::MissingManagedBody { semantic_trace, .. } => Some(semantic_trace),
            Self::NodeLimit { .. } => None,
        }
    }

    #[must_use]
    pub(crate) const fn node_limit_value(&self) -> Option<u64> {
        match self {
            Self::MissingManagedBody { .. } => None,
            Self::NodeLimit { limit } => Some(*limit),
        }
    }

    #[must_use]
    pub(crate) const fn source(&self) -> Option<&ScopedEntityRef> {
        match self {
            Self::MissingManagedBody {
                presentation_source,
                ..
            } => match presentation_source {
                Some(source) => Some(source.anchor()),
                None => None,
            },
            Self::NodeLimit { .. } => None,
        }
    }

    #[must_use]
    pub(crate) const fn trace(&self) -> Option<&RelationTrace> {
        match self {
            Self::MissingManagedBody { relation_trace, .. } => Some(relation_trace),
            Self::NodeLimit { .. } => None,
        }
    }
}

/// Exact presentation anchor paired with its scope-independent source value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct PanicCompletenessSource {
    anchor: ScopedEntityRef,
    key: SourceAnchorKey,
}

impl PanicCompletenessSource {
    #[must_use]
    pub(crate) const fn new(anchor: ScopedEntityRef, key: SourceAnchorKey) -> Self {
        Self { anchor, key }
    }

    #[must_use]
    pub(crate) const fn anchor(&self) -> &ScopedEntityRef {
        &self.anchor
    }

    #[must_use]
    pub(crate) const fn key(&self) -> &SourceAnchorKey {
        &self.key
    }
}

/// One scope-independent step matching the legacy interpreted trace value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct PanicCompletenessSemanticStep {
    caller: FunctionKey,
    caller_path: String,
    call_local_id: u32,
    kind: CallKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<SourceAnchorKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<FunctionKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_path: Option<String>,
}

impl PanicCompletenessSemanticStep {
    #[allow(
        clippy::too_many_arguments,
        reason = "the semantic trace step mirrors each legacy equality field"
    )]
    #[must_use]
    pub(crate) fn new(
        caller: FunctionKey,
        caller_path: impl Into<String>,
        call_local_id: u32,
        kind: CallKind,
        source: Option<SourceAnchorKey>,
        target: Option<FunctionKey>,
        target_path: Option<String>,
    ) -> Self {
        Self {
            caller,
            caller_path: caller_path.into(),
            call_local_id,
            kind,
            source,
            target,
            target_path,
        }
    }

    #[must_use]
    pub(crate) const fn caller(&self) -> FunctionKey {
        self.caller
    }

    #[must_use]
    pub(crate) fn caller_path(&self) -> &str {
        &self.caller_path
    }

    #[must_use]
    pub(crate) const fn call_local_id(&self) -> u32 {
        self.call_local_id
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> CallKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn source(&self) -> Option<&SourceAnchorKey> {
        self.source.as_ref()
    }

    #[must_use]
    pub(crate) const fn target(&self) -> Option<FunctionKey> {
        self.target
    }

    #[must_use]
    pub(crate) fn target_path(&self) -> Option<&str> {
        self.target_path.as_deref()
    }
}

/// One ordered reason retained by a root's completeness summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct PanicCompletenessReason {
    traversal_order: u64,
    reason: PanicIncompleteReason,
}

impl PanicCompletenessReason {
    #[must_use]
    pub(crate) fn missing_managed_body(
        traversal_order: u64,
        function: FunctionKey,
        path: impl Into<String>,
        presentation_source: Option<PanicCompletenessSource>,
        semantic_trace: Vec<PanicCompletenessSemanticStep>,
        relation_trace: RelationTrace,
    ) -> Self {
        Self {
            traversal_order,
            reason: PanicIncompleteReason::MissingManagedBody {
                function,
                path: path.into(),
                presentation_source,
                semantic_trace,
                relation_trace,
            },
        }
    }

    #[must_use]
    pub(crate) const fn node_limit(traversal_order: u64, limit: u64) -> Self {
        Self {
            traversal_order,
            reason: PanicIncompleteReason::NodeLimit { limit },
        }
    }

    #[must_use]
    pub(crate) const fn traversal_order(&self) -> u64 {
        self.traversal_order
    }

    #[must_use]
    pub(crate) const fn reason(&self) -> &PanicIncompleteReason {
        &self.reason
    }
}

/// One validated, root-scoped panic traversal completeness outcome.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct PanicCompletenessOutcome {
    expanded_bodies: u64,
    reasons: Vec<PanicCompletenessReason>,
}

impl RowSchema for PanicCompletenessOutcome {
    const ID: &'static str = "sniff-test.panic.completeness-outcome";
    const VERSION: u32 = 1;
}

impl DerivedSchema for PanicCompletenessOutcome {}

impl PanicCompletenessOutcome {
    #[must_use]
    pub(crate) const fn new(expanded_bodies: u64, reasons: Vec<PanicCompletenessReason>) -> Self {
        Self {
            expanded_bodies,
            reasons,
        }
    }

    #[must_use]
    pub(crate) const fn expanded_bodies(&self) -> u64 {
        self.expanded_bodies
    }

    #[must_use]
    pub(crate) fn reasons(&self) -> &[PanicCompletenessReason] {
        &self.reasons
    }

    #[must_use]
    pub(crate) fn complete(&self) -> bool {
        self.reasons.is_empty()
    }
}

/// A validated completeness outcome selected for panic-analysis reporting.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct PanicAnalysisIncompleteIssue {
    traversal_order: u64,
    reason: PanicIncompleteReason,
}

impl RowSchema for PanicAnalysisIncompleteIssue {
    const ID: &'static str = "sniff-test.panic.analysis-incomplete";
    const VERSION: u32 = 1;
}

impl IssueSchema for PanicAnalysisIncompleteIssue {}

impl PanicAnalysisIncompleteIssue {
    #[must_use]
    pub(crate) fn from_reason(reason: PanicCompletenessReason) -> Self {
        Self {
            traversal_order: reason.traversal_order,
            reason: reason.reason,
        }
    }

    #[must_use]
    pub(crate) const fn traversal_order(&self) -> u64 {
        self.traversal_order
    }

    #[must_use]
    pub(crate) const fn reason(&self) -> &PanicIncompleteReason {
        &self.reason
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct LegacySemanticStepKey {
    caller: FunctionKey,
    caller_path: String,
    call_local_id: u32,
    kind: CallKind,
    source: Option<SourceAnchorKey>,
    target: Option<FunctionKey>,
    target_path: Option<String>,
}

impl From<&PanicCompletenessSemanticStep> for LegacySemanticStepKey {
    fn from(step: &PanicCompletenessSemanticStep) -> Self {
        Self {
            caller: step.caller(),
            caller_path: step.caller_path().to_owned(),
            call_local_id: step.call_local_id(),
            kind: step.kind(),
            source: step.source().cloned(),
            target: step.target(),
            target_path: step.target_path().map(str::to_owned),
        }
    }
}

/// Scope-independent equality of one legacy missing-body reason.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct LegacyMissingBodyKey {
    function: FunctionKey,
    path: String,
    presentation_source: Option<SourceAnchorKey>,
    semantic_trace: Vec<LegacySemanticStepKey>,
}

impl LegacyMissingBodyKey {
    fn from_reason(reason: &PanicIncompleteReason) -> Option<Self> {
        let PanicIncompleteReason::MissingManagedBody {
            function,
            path,
            presentation_source,
            semantic_trace,
            ..
        } = reason
        else {
            return None;
        };
        Some(Self {
            function: *function,
            path: path.clone(),
            presentation_source: presentation_source
                .as_ref()
                .map(|source| source.key().clone()),
            semantic_trace: semantic_trace.iter().map(Into::into).collect(),
        })
    }
}

/// Completeness projection installed in the unified typed-panic authority.
pub(crate) struct PanicCompletenessPack;

impl AnalysisPack<PanicRootInputs> for PanicCompletenessPack {
    fn register(
        &self,
        registry: &mut AnalysisRegistry<PanicRootInputs>,
    ) -> Result<(), PackRegistrationError> {
        registry.register_derived::<PanicCompletenessOutcome>()?;
        registry.register_issue::<PanicAnalysisIncompleteIssue>()?;
        registry.register_issue_renderer::<PanicAnalysisIncompleteIssue, _>(
            PanicAnalysisIncompleteRenderer,
        )?;
        registry.register_evaluation_rule(EmitPanicCompleteness)?;
        registry.register_evaluation_rule(ReportPanicIncomplete)?;
        Ok(())
    }
}

struct EmitPanicCompleteness;

impl EvaluationRule<PanicRootInputs> for EmitPanicCompleteness {
    fn descriptor(&self) -> RuleDescriptor {
        completeness_projection_descriptor(EMIT_PANIC_COMPLETENESS_RULE)
            .write_derived::<PanicCompletenessOutcome>()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, PanicRootInputs>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        validate_context(cx, input)?;
        if cx.root().domain != panic_domain() {
            return Ok(());
        }
        let summary = project_summary(cx.services(), input, output)?;
        output.emit_derived(&summary)
    }
}

struct ReportPanicIncomplete;

impl EvaluationRule<PanicRootInputs> for ReportPanicIncomplete {
    fn descriptor(&self) -> RuleDescriptor {
        completeness_projection_descriptor(REPORT_PANIC_INCOMPLETE_RULE)
            .read::<PanicCompletenessOutcome>()
            .write_issue::<PanicAnalysisIncompleteIssue>()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, PanicRootInputs>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        validate_context(cx, input)?;
        if cx.root().domain != panic_domain() {
            return Ok(());
        }

        let rows = input.derived_rows::<PanicCompletenessOutcome>()?;
        let [row] = rows.as_slice() else {
            return Err(RuleError::failed(format!(
                "panic completeness requires exactly one summary row for the active root, found {}",
                rows.len()
            )));
        };
        if row.root != *cx.root() {
            return Err(RuleError::failed(
                "panic completeness summary belongs to a different evaluation root",
            ));
        }
        if row.producer != PassId::new(EMIT_PANIC_COMPLETENESS_RULE).unwrap() {
            return Err(RuleError::failed(format!(
                "panic completeness summary has unexpected producer `{}`",
                row.producer.as_str()
            )));
        }
        validate_summary_shape(&row.data)?;
        let expected = project_summary(cx.services(), input, output)?;
        if row.data != expected {
            return Err(RuleError::failed(
                "committed panic completeness summary disagrees with resolved traversal inputs",
            ));
        }

        let pending = prepare_issues(&row.data, cx.root());
        for (issue, context) in pending {
            output.emit_issue(&issue, context)?;
        }
        Ok(())
    }
}

fn completeness_projection_descriptor(rule: &'static str) -> RuleDescriptor {
    RuleDescriptor::new(PassId::new(rule).unwrap())
        .read::<FunctionEntity>()
        .read::<CallOccurrenceEntity>()
        .read::<CallSiteEntity>()
        .read::<CallMacroExpansionEntity>()
        .read::<CallableEntity>()
        .read::<SourceAnchorEntity>()
}

fn validate_context(
    cx: &EvaluationCx<'_, PanicRootInputs>,
    input: &EvaluationInput<'_>,
) -> Result<(), RuleError> {
    if !input.has_workspace_identity(cx.services().workspace_identity()) {
        return Err(RuleError::failed(
            "panic completeness inputs belong to a replacement workspace fact view",
        ));
    }
    if cx.services().root() != cx.root() {
        return Err(RuleError::failed(
            "panic completeness inputs belong to a different evaluation root",
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear pass keeps selective outcome mapping and atomic summary construction auditable"
)]
fn project_summary(
    services: &PanicRootInputs,
    input: &EvaluationInput<'_>,
    output: &EvaluationOutput<'_>,
) -> Result<PanicCompletenessOutcome, RuleError> {
    let traversal = services.traversal();
    if traversal.root() != services.root() {
        return Err(RuleError::failed(
            "panic completeness traversal root disagrees with its prepared inputs",
        ));
    }
    project_traversal_summary(traversal, input, output)
}

/// Projects the domain-neutral root traversal completeness contract.
///
/// Safety and panic own distinct derived/issue schemas but share this strict
/// traversal and presentation proof so their incomplete reasons cannot drift.
#[allow(
    clippy::too_many_lines,
    reason = "one linear pass keeps selective outcome mapping and atomic summary construction auditable"
)]
pub(crate) fn project_traversal_summary<B>(
    traversal: &ResolvedRootProgramTraversal<B>,
    input: &EvaluationInput<'_>,
    output: &EvaluationOutput<'_>,
) -> Result<PanicCompletenessOutcome, RuleError> {
    for visit in traversal.body_visits() {
        validate_body_visit(visit, input, output)?;
    }
    let expanded_bodies = u64::try_from(traversal.body_visits().len()).map_err(|_| {
        RuleError::failed("panic completeness expanded-body count does not fit u64")
    })?;

    validate_strict_orders(
        traversal
            .followed_calls()
            .iter()
            .map(ResolvedFollowedCall::order),
        "followed calls",
    )?;
    validate_strict_orders(
        traversal
            .outcomes()
            .iter()
            .map(ResolvedTraversalOutcome::order),
        "outcomes",
    )?;
    let mut selector = None;
    let mut followed_cursor = 0;
    let mut missing = HashSet::<LegacyMissingBodyKey>::new();
    let mut node_limit = None::<(u64, u64)>;
    let mut reasons = Vec::new();

    for outcome in traversal.outcomes() {
        match outcome.kind() {
            TraversalOutcomeKind::MissingManagedBody {
                preferred_scope,
                defining_scope: _,
                stable_crate_id,
                requested,
            } => {
                output.validate_relation_trace(outcome.trace())?;
                let predecessor = outcome.order().checked_sub(1).ok_or_else(|| {
                    RuleError::failed(
                        "missing managed body cannot precede its entering followed call",
                    )
                })?;
                while traversal
                    .followed_calls()
                    .get(followed_cursor)
                    .is_some_and(|call| call.order() < predecessor)
                {
                    followed_cursor += 1;
                }
                let terminal = traversal
                    .followed_calls()
                    .get(followed_cursor)
                    .filter(|call| call.order() == predecessor)
                    .ok_or_else(|| {
                        RuleError::failed(format!(
                            "missing managed body at traversal order {} has no consecutive entering call",
                            outcome.order()
                        ))
                    })?;
                followed_cursor += 1;
                let selector =
                    selector.get_or_insert_with(|| TraceRouteSelector::prepare(traversal));
                let (key, reason) = project_missing_managed_body(
                    selector,
                    terminal,
                    outcome.order(),
                    outcome.trace(),
                    preferred_scope,
                    *stable_crate_id,
                    *requested,
                    input,
                    output,
                )?;
                retain_missing_reason(&mut missing, &mut reasons, key, reason);
            }
            TraversalOutcomeKind::BudgetExceeded { limit } => {
                output.validate_relation_trace(outcome.trace())?;
                let limit = u64::try_from(*limit).map_err(|_| {
                    RuleError::failed("panic completeness node limit does not fit u64")
                })?;
                match node_limit {
                    Some((_, existing)) if existing != limit => {
                        return Err(RuleError::failed(format!(
                            "panic traversal recorded inconsistent node limits {existing} and {limit}"
                        )));
                    }
                    Some(_) => {}
                    None => {
                        node_limit = Some((outcome.order(), limit));
                        reasons.push(PanicCompletenessReason::node_limit(outcome.order(), limit));
                    }
                }
            }
            TraversalOutcomeKind::Ignored
            | TraversalOutcomeKind::UnmanagedStableCrate { .. }
            | TraversalOutcomeKind::UnmanagedDefiningSource { .. }
            | TraversalOutcomeKind::MissingManagedDefiningSource { .. }
            | TraversalOutcomeKind::Cycle
            | TraversalOutcomeKind::Deduplicated => {}
        }
    }

    let outcome = PanicCompletenessOutcome::new(expanded_bodies, reasons);
    validate_summary_shape(&outcome)?;
    Ok(outcome)
}

fn retain_missing_reason(
    seen: &mut HashSet<LegacyMissingBodyKey>,
    reasons: &mut Vec<PanicCompletenessReason>,
    key: LegacyMissingBodyKey,
    reason: PanicCompletenessReason,
) {
    if seen.insert(key) {
        reasons.push(reason);
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "missing-body projection validates every independent traversal identity"
)]
fn project_missing_managed_body(
    selector: &mut TraceRouteSelector<'_>,
    terminal: &ResolvedFollowedCall,
    outcome_order: u64,
    outcome_trace: &RelationTrace,
    preferred_scope: &crate::analysis::facts::workspace::ArtifactScopeId,
    stable_crate_id: u64,
    requested: FunctionKey,
    input: &EvaluationInput<'_>,
    output: &EvaluationOutput<'_>,
) -> Result<(LegacyMissingBodyKey, PanicCompletenessReason), RuleError> {
    if terminal.order().checked_add(1) != Some(outcome_order)
        || terminal.trace() != outcome_trace
        || terminal.target_data().key() != &requested
    {
        return Err(RuleError::failed(format!(
            "missing managed body at traversal order {outcome_order} disagrees with its consecutive entering call"
        )));
    }
    validate_followed_call(terminal, input, output)?;
    if terminal.target().callable().scope() != preferred_scope {
        return Err(RuleError::failed(
            "missing managed body preferred scope disagrees with its entering callable",
        ));
    }
    if requested.definition().stable_crate_id() != stable_crate_id {
        return Err(RuleError::failed(
            "missing managed body stable-crate identity disagrees with its requested function",
        ));
    }
    if outcome_trace.target() != &terminal.target().callable().erase() {
        return Err(RuleError::failed(
            "missing managed body trace does not target its entering callable",
        ));
    }

    let endpoint =
        TraceRouteEndpoint::new(outcome_order, outcome_trace, terminal.inherited_markers());
    let route = selector.select_route(endpoint).map_err(|error| {
        RuleError::failed(format!("invalid missing-body trace route: {error:?}"))
    })?;
    let caller = selector
        .select_terminal_caller(
            &terminal.occurrence().erase(),
            *terminal.occurrence_data().key().owner(),
            terminal.inherited_markers(),
            terminal.trace(),
        )
        .map_err(|error| {
            RuleError::failed(format!("invalid missing-body terminal caller: {error:?}"))
        })?;

    let mut semantic_trace = Vec::new();
    for selected in route.calls() {
        append_semantic_call(
            &mut semantic_trace,
            selected.caller(),
            selected.call(),
            input,
            output,
        )?;
    }
    append_semantic_call(&mut semantic_trace, caller, terminal, input, output)?;

    let presentation_source = unique_call_anchor(
        terminal.source_anchors(),
        CallSourceAnchorRole::Presentation,
    )?
    .map(|source| {
        validate_source_anchor(source.anchor(), source.key(), input)?;
        Ok(PanicCompletenessSource::new(
            source.anchor().erase(),
            source.key().clone(),
        ))
    })
    .transpose()?;
    let path = terminal.target_data().display_path().to_owned();
    let reason = PanicCompletenessReason::missing_managed_body(
        outcome_order,
        requested,
        path,
        presentation_source,
        semantic_trace,
        outcome_trace.clone(),
    );
    let key = LegacyMissingBodyKey::from_reason(reason.reason())
        .expect("a missing-body reason always has a legacy semantic key");
    Ok((key, reason))
}

fn append_semantic_call(
    steps: &mut Vec<PanicCompletenessSemanticStep>,
    caller: &ResolvedBodyVisit,
    call: &ResolvedFollowedCall,
    input: &EvaluationInput<'_>,
    output: &EvaluationOutput<'_>,
) -> Result<(), RuleError> {
    validate_body_visit(caller, input, output)?;
    validate_followed_call(call, input, output)?;

    let call_local_id = call.occurrence_data().key().local_id();
    let mut caller_key = caller.function();
    let mut caller_path = caller.data().display_path().to_owned();
    for frame in call.macro_frames() {
        validate_entity_snapshot(input, frame.frame(), frame.data(), "call macro frame")?;
        let source = frame
            .callsite()
            .map(|callsite| {
                validate_source_anchor(callsite.anchor(), callsite.key(), input)?;
                Ok(callsite.key().clone())
            })
            .transpose()?;
        let target = FunctionKey::new(frame.data().macro_definition(), None);
        let target_path = format!("macro {}", frame.data().display_path());
        steps.push(PanicCompletenessSemanticStep::new(
            caller_key,
            caller_path,
            call_local_id,
            CallKind::MacroExpansion,
            source,
            Some(target),
            Some(target_path.clone()),
        ));
        caller_key = target;
        caller_path = target_path;
    }

    let expanded = unique_call_anchor(call.source_anchors(), CallSourceAnchorRole::Expanded)?;
    let presentation =
        unique_call_anchor(call.source_anchors(), CallSourceAnchorRole::Presentation)?;
    let source = expanded.or(presentation).map(|anchor| anchor.key().clone());
    steps.push(PanicCompletenessSemanticStep::new(
        caller_key,
        caller_path,
        call_local_id,
        call.effective_kind(),
        source,
        Some(*call.target_data().key()),
        Some(call.target_data().display_path().to_owned()),
    ));
    Ok(())
}

fn unique_call_anchor(
    anchors: &[ResolvedCallSourceAnchor],
    role: CallSourceAnchorRole,
) -> Result<Option<&ResolvedCallSourceAnchor>, RuleError> {
    let mut selected = anchors.iter().filter(|anchor| anchor.role() == role);
    let first = selected.next();
    if selected.next().is_some() {
        return Err(RuleError::failed(format!(
            "followed call has more than one {role:?} source anchor"
        )));
    }
    Ok(first)
}

fn validate_body_visit(
    visit: &ResolvedBodyVisit,
    input: &EvaluationInput<'_>,
    output: &EvaluationOutput<'_>,
) -> Result<(), RuleError> {
    validate_entity_snapshot(input, visit.body(), visit.data(), "visited function body")?;
    output.validate_relation_trace(visit.trace())
}

fn validate_followed_call(
    call: &ResolvedFollowedCall,
    input: &EvaluationInput<'_>,
    output: &EvaluationOutput<'_>,
) -> Result<(), RuleError> {
    validate_entity_snapshot(
        input,
        call.occurrence(),
        call.occurrence_data(),
        "followed call occurrence",
    )?;
    validate_entity_snapshot(
        input,
        call.call_site(),
        call.call_site_data(),
        "followed call site",
    )?;
    validate_entity_snapshot(
        input,
        call.target().callable(),
        call.target_data(),
        "followed callable",
    )?;
    match call.resolution() {
        ProgramCallResolution::Persisted if call.effective_kind() != call.kind() => {
            return Err(RuleError::failed(
                "persisted followed call has an inconsistent effective kind",
            ));
        }
        ProgramCallResolution::CallableEvidence { .. }
            if call.target().role() != CallTargetRole::Runtime
                || call.target().authority() != ReconciledCallTargetAuthority::ConsumerRaw =>
        {
            return Err(RuleError::failed(
                "callable-evidence follow does not use its synthetic runtime target authority",
            ));
        }
        ProgramCallResolution::Persisted | ProgramCallResolution::CallableEvidence { .. } => {}
    }
    if call.trace().target() != &call.target().callable().erase() {
        return Err(RuleError::failed(
            "followed call trace does not target its selected callable",
        ));
    }
    for anchor in call.source_anchors() {
        validate_source_anchor(anchor.anchor(), anchor.key(), input)?;
    }
    for frame in call.macro_frames() {
        validate_entity_snapshot(input, frame.frame(), frame.data(), "call macro frame")?;
        if let Some(callsite) = frame.callsite() {
            validate_source_anchor(callsite.anchor(), callsite.key(), input)?;
        }
    }
    output.validate_relation_trace(call.trace())
}

fn validate_source_anchor(
    anchor: &ScopedEntityId<SourceAnchorEntity>,
    key: &SourceAnchorKey,
    input: &EvaluationInput<'_>,
) -> Result<(), RuleError> {
    let persisted = input.artifact_entity_at::<SourceAnchorEntity>(&anchor.erase())?;
    if persisted.anchor() != key {
        return Err(RuleError::failed(
            "resolved source anchor disagrees with its exact artifact entity",
        ));
    }
    Ok(())
}

fn validate_entity_snapshot<E>(
    input: &EvaluationInput<'_>,
    reference: &ScopedEntityId<E>,
    expected: &E,
    label: &'static str,
) -> Result<(), RuleError>
where
    E: EntitySchema + PartialEq,
{
    if input.artifact_entity_at::<E>(&reference.erase())? != *expected {
        return Err(RuleError::failed(format!(
            "resolved {label} disagrees with its exact artifact entity"
        )));
    }
    Ok(())
}

fn validate_summary_shape(summary: &PanicCompletenessOutcome) -> Result<(), RuleError> {
    let mut previous_order = None;
    let mut missing = HashSet::new();
    let mut node_limit = None;
    for reason in summary.reasons() {
        if previous_order.is_some_and(|previous| previous >= reason.traversal_order()) {
            return Err(RuleError::failed(
                "panic completeness reasons are not in strict canonical order",
            ));
        }
        previous_order = Some(reason.traversal_order());
        match reason.reason() {
            PanicIncompleteReason::MissingManagedBody { .. } => {
                let key = LegacyMissingBodyKey::from_reason(reason.reason())
                    .expect("the matched variant has a legacy key");
                if !missing.insert(key) {
                    return Err(RuleError::failed(
                        "panic completeness contains duplicate legacy missing-body reasons",
                    ));
                }
            }
            PanicIncompleteReason::NodeLimit { limit } => {
                if node_limit.replace(*limit).is_some() {
                    return Err(RuleError::failed(
                        "panic completeness contains more than one node-limit reason",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_strict_orders(
    orders: impl IntoIterator<Item = u64>,
    label: &'static str,
) -> Result<(), RuleError> {
    let mut previous = None;
    for order in orders {
        if previous.is_some_and(|previous| previous >= order) {
            return Err(RuleError::failed(format!(
                "panic traversal {label} are not in strict traversal order"
            )));
        }
        previous = Some(order);
    }
    Ok(())
}

fn prepare_issues(
    summary: &PanicCompletenessOutcome,
    root: &crate::analysis::facts::evaluation::EvaluationRoot,
) -> Vec<(PanicAnalysisIncompleteIssue, EvaluationIssueContext)> {
    summary
        .reasons()
        .iter()
        .cloned()
        .map(|reason| {
            let mut context = EvaluationIssueContext::new(root.clone());
            if let PanicIncompleteReason::MissingManagedBody {
                presentation_source,
                relation_trace,
                ..
            } = reason.reason()
            {
                if let Some(source) = presentation_source {
                    context = context.with_source(source.anchor().as_row());
                }
                context = context
                    .with_endpoint(relation_trace.target().clone())
                    .with_trace(relation_trace.clone());
            }
            (PanicAnalysisIncompleteIssue::from_reason(reason), context)
        })
        .collect()
}

struct PanicAnalysisIncompleteRenderer;

impl IssueRenderer<PanicAnalysisIncompleteIssue> for PanicAnalysisIncompleteRenderer {
    fn render(
        &self,
        issue: &PanicAnalysisIncompleteIssue,
        _cx: &RenderCx<'_>,
    ) -> RenderedDiagnostic {
        let mut diagnostic = match issue.reason() {
            PanicIncompleteReason::MissingManagedBody { function, path, .. } => {
                let mut diagnostic = RenderedDiagnostic::new(format!(
                    "panic analysis could not inspect managed body `{path}`"
                ));
                diagnostic.notes.push(String::from(
                    "results may be incomplete because a reached managed function body was unavailable",
                ));
                diagnostic.data = json!({
                    "kind": "missing-managed-body",
                    "function": function,
                    "path": path,
                });
                diagnostic
            }
            PanicIncompleteReason::NodeLimit { limit } => {
                let mut diagnostic = RenderedDiagnostic::new(format!(
                    "panic analysis reached the configured node limit ({limit})"
                ));
                diagnostic.help.push(String::from(
                    "increase the analysis node limit to inspect more reachable bodies",
                ));
                diagnostic.data = json!({
                    "kind": "node-limit",
                    "limit": limit,
                });
                diagnostic
            }
        };
        diagnostic
            .sort_key
            .push(format!("{:020}", issue.traversal_order()));
        diagnostic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::cache::RustcArtifactId;
    use crate::analysis::facts::builder::ArtifactDbBuilder;
    use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
    use crate::analysis::facts::composition::{
        CompositionRelationBuilder, WorkspaceEvaluationView, WorkspaceRelationGraph,
    };
    use crate::analysis::facts::encoded::EntityRef;
    use crate::analysis::facts::encoded::TableKind;
    use crate::analysis::facts::evaluation::{EvaluationDb, RelationTrace};
    use crate::analysis::facts::pack::{AnalysisPack, AnalysisRegistry};
    use crate::analysis::facts::panic::PanicRootInputs;
    use crate::analysis::facts::panic::compiler_assert_inputs::{
        CompilerAssertRootRequest, PreparedCompilerAssertRootBatch,
    };
    use crate::analysis::facts::panic::compiler_assert_trace::tests::{
        attach_named_call_macros_and_sources, attach_panic_marker_to_call, insert_callable,
        insert_direct_call, insert_function,
    };
    use crate::analysis::facts::panic::trace_route::{
        TraceRouteWork, reset_trace_route_work, trace_route_work,
    };
    use crate::analysis::facts::program::root_traversal::{MarkerProbe, TraversalOutcomeKind};
    use crate::analysis::facts::program::topology::{
        CallAttributionRole, CallKind, CallMacroExpansionEntity, CallOccurrenceEntity,
        CallOccurrenceInSafetyEffectGroup, CallOccurrenceKey, CallOccurrenceTargetsCallable,
        CallSiteEntity, CallSiteHasOccurrence, CallSiteKey, CallTargetRole, CallableEntity,
        FunctionDefinesCallable, FunctionOwnsCallSite, FunctionOwnsSafetyEffectGroup,
        SafetyEffectGroupEntity, SafetyEffectGroupKey,
    };
    use crate::analysis::facts::program::{
        FunctionBodyProvenance, FunctionEntity, FunctionKey, SourceAnchorEntity,
    };
    use crate::analysis::facts::schema::{EntityHandle, PassId, RowSchema, SchemaId};
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::analysis::facts::workspace::{ArtifactScopeId, ScopedEntityRef, WorkspaceFactView};
    use crate::analysis::workspace_closure::{
        ManagedArtifactGeneration, ManagedArtifactManifest, VerifiedWorkspaceClosure,
    };
    use crate::config::PanicConfig;
    use crate::contracts::ContractDocOverrides;
    use crate::namespace::{StableDefPathHash, StableInstanceHash};

    fn function(local: u64) -> FunctionKey {
        function_in(1, local)
    }

    fn function_in(stable_crate_id: u64, local: u64) -> FunctionKey {
        let definition = serde_json::from_str::<StableDefPathHash>(&format!(
            "\"{stable_crate_id:016x}{local:016x}\""
        ))
        .unwrap();
        let instance =
            serde_json::from_str::<StableInstanceHash>(&format!("\"{local:032x}\"")).unwrap();
        FunctionKey::new(definition, Some(instance))
    }

    fn endpoint(scope: &ArtifactScopeId, row: u32) -> ScopedEntityRef {
        ScopedEntityRef::new(
            scope.clone(),
            EntityRef {
                schema: SchemaId::new("test.panic.completeness-endpoint").unwrap(),
                row,
            },
        )
    }

    fn completeness_registry() -> AnalysisRegistry<PanicRootInputs> {
        let mut registry = AnalysisRegistry::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        registry.install(&PanicCompletenessPack).unwrap();
        registry
    }

    fn declared_artifact_builder(
        registry: &AnalysisRegistry<PanicRootInputs>,
    ) -> ArtifactDbBuilder {
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors().filter(|descriptor| {
            !matches!(descriptor.kind(), TableKind::Derived | TableKind::Issue)
        }) {
            builder.declare_table(descriptor).unwrap();
        }
        builder
    }

    fn insert_call_with_distinct_site_id(
        builder: &mut ArtifactDbBuilder,
        owner_body: &EntityHandle<FunctionEntity>,
        owner: FunctionKey,
        occurrence_local_id: u32,
        call_site_local_id: u32,
        target: &EntityHandle<CallableEntity>,
    ) -> EntityHandle<CallOccurrenceEntity> {
        let call_site = builder
            .insert_entity(&CallSiteEntity::new(CallSiteKey::new(
                owner,
                call_site_local_id,
            )))
            .unwrap();
        let occurrence = builder
            .insert_entity(&CallOccurrenceEntity::new(
                CallOccurrenceKey::new(owner, occurrence_local_id),
                CallKind::DirectCall,
                vec![CallAttributionRole::CallSite],
                false,
                false,
                None,
            ))
            .unwrap();
        let safety_group = builder
            .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                owner,
                occurrence_local_id,
            )))
            .unwrap();
        builder
            .relate(owner_body, &call_site, &FunctionOwnsCallSite::new())
            .unwrap();
        builder
            .relate(&call_site, &occurrence, &CallSiteHasOccurrence::new())
            .unwrap();
        builder
            .relate(
                owner_body,
                &safety_group,
                &FunctionOwnsSafetyEffectGroup::new(),
            )
            .unwrap();
        builder
            .relate(
                &occurrence,
                &safety_group,
                &CallOccurrenceInSafetyEffectGroup::new(),
            )
            .unwrap();
        builder
            .relate(
                &occurrence,
                target,
                &CallOccurrenceTargetsCallable::new(CallTargetRole::Runtime),
            )
            .unwrap();
        occurrence
    }

    fn insert_consumer_function(
        builder: &mut ArtifactDbBuilder,
        key: FunctionKey,
        consumer_stable_crate_id: u64,
        path: &str,
    ) {
        let body = builder
            .insert_entity(&FunctionEntity::new(
                key,
                path,
                FunctionBodyProvenance::ConsumerInstantiation {
                    consumer_stable_crate_id,
                },
            ))
            .unwrap();
        let callable = insert_callable(builder, key, path);
        builder
            .relate(&body, &callable, &FunctionDefinesCallable::new())
            .unwrap();
    }

    fn with_single_artifact_inputs(
        node_budget: usize,
        unmanaged: Vec<RustcArtifactId>,
        build: impl FnOnce(&mut ArtifactDbBuilder) -> FunctionKey,
        test: impl FnOnce(
            &AnalysisRegistry<PanicRootInputs>,
            &WorkspaceFactView<'_>,
            PanicRootInputs,
            WorkspaceRelationGraph,
        ),
    ) {
        let registry = completeness_registry();
        with_registry_single_artifact_inputs(&registry, node_budget, unmanaged, build, test);
    }

    fn with_registry_single_artifact_inputs(
        registry: &AnalysisRegistry<PanicRootInputs>,
        node_budget: usize,
        unmanaged: Vec<RustcArtifactId>,
        build: impl FnOnce(&mut ArtifactDbBuilder) -> FunctionKey,
        test: impl FnOnce(
            &AnalysisRegistry<PanicRootInputs>,
            &WorkspaceFactView<'_>,
            PanicRootInputs,
            WorkspaceRelationGraph,
        ),
    ) {
        let mut builder = declared_artifact_builder(registry);
        let root = build(&mut builder);
        let artifact = builder.finalize(registry.schemas()).unwrap();
        let scope = ArtifactScopeId::for_in_memory(1, 0);
        let workspace = WorkspaceFactView::compose([(
            scope,
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let closure = VerifiedWorkspaceClosure::open_with_runtime_inventory(
            &workspace,
            ManagedArtifactManifest::new(ManagedArtifactGeneration::in_memory(1, 0), vec![]),
            [],
            unmanaged,
        )
        .unwrap();
        let prepared = PreparedCompilerAssertRootBatch::prepare(
            &workspace,
            &closure,
            &PanicConfig::default(),
            &ContractDocOverrides::default(),
            [CompilerAssertRootRequest::new(
                root,
                CallAttributionRole::CallSite,
                MarkerProbe::SourceCallsite,
                node_budget,
            )],
        )
        .unwrap()
        .into_roots()
        .pop()
        .unwrap();
        let mut composition = CompositionRelationBuilder::new(
            prepared.root(),
            &workspace,
            registry.composition_relations(),
        )
        .unwrap();
        let emitted = prepared.emit(&mut composition).unwrap();
        let relations = composition.finalize().unwrap();
        let graph = WorkspaceRelationGraph::new(emitted.root(), &workspace, &relations).unwrap();
        let inputs = emitted
            .resolve_panic(&workspace, &graph, registry.composition_relations())
            .unwrap();
        test(registry, &workspace, inputs, graph);
    }

    fn evaluate(
        registry: &AnalysisRegistry<PanicRootInputs>,
        workspace: &WorkspaceFactView<'_>,
        inputs: &PanicRootInputs,
        graph: WorkspaceRelationGraph,
    ) -> crate::analysis::facts::evaluation::EvaluationResults {
        let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
        let mut evaluated = EvaluationDb::new();
        registry
            .run_workspace_evaluation(inputs, inputs.root(), &evaluation, &mut evaluated)
            .unwrap();
        evaluated.finish().unwrap()
    }

    #[derive(Clone, Copy)]
    enum SeedSummaryMode {
        Missing,
        Duplicate,
        WrongProducer,
        AlteredCount,
        AlteredReason,
        SemanticDuplicate,
        LateAlteredReason,
    }

    struct SeedCompletenessSummary(SeedSummaryMode);

    impl EvaluationRule<PanicRootInputs> for SeedCompletenessSummary {
        fn descriptor(&self) -> RuleDescriptor {
            let rule = if matches!(self.0, SeedSummaryMode::WrongProducer) {
                "test.panic.seed-completeness-wrong-producer"
            } else {
                EMIT_PANIC_COMPLETENESS_RULE
            };
            RuleDescriptor::new(PassId::new(rule).unwrap())
                .write_derived::<PanicCompletenessOutcome>()
        }

        fn evaluate(
            &self,
            cx: &EvaluationCx<'_, PanicRootInputs>,
            _input: &EvaluationInput<'_>,
            output: &mut EvaluationOutput<'_>,
        ) -> Result<(), RuleError> {
            if cx.root().domain != panic_domain() || matches!(self.0, SeedSummaryMode::Missing) {
                return Ok(());
            }
            let outcome = cx
                .services()
                .traversal()
                .outcomes()
                .iter()
                .find_map(|outcome| match outcome.kind() {
                    TraversalOutcomeKind::BudgetExceeded { limit } => {
                        Some((outcome.order(), u64::try_from(*limit).unwrap()))
                    }
                    _ => None,
                })
                .expect("the hostile fixture uses a zero-budget root");
            let expected = PanicCompletenessOutcome::new(
                0,
                vec![PanicCompletenessReason::node_limit(outcome.0, outcome.1)],
            );
            match self.0 {
                SeedSummaryMode::Missing => unreachable!(),
                SeedSummaryMode::Duplicate => {
                    output.emit_derived(&expected)?;
                    output.emit_derived(&expected)
                }
                SeedSummaryMode::WrongProducer => output.emit_derived(&expected),
                SeedSummaryMode::AlteredCount => output.emit_derived(
                    &PanicCompletenessOutcome::new(1, expected.reasons().to_vec()),
                ),
                SeedSummaryMode::AlteredReason => {
                    output.emit_derived(&PanicCompletenessOutcome::new(
                        0,
                        vec![PanicCompletenessReason::node_limit(
                            outcome.0,
                            outcome.1 + 1,
                        )],
                    ))
                }
                SeedSummaryMode::SemanticDuplicate => {
                    let first = fake_missing_reason(cx, outcome.0 + 1, 0, 7);
                    let duplicate = fake_missing_reason(cx, outcome.0 + 2, 1, 7);
                    output.emit_derived(&PanicCompletenessOutcome::new(0, vec![first, duplicate]))
                }
                SeedSummaryMode::LateAlteredReason => {
                    let late = fake_missing_reason(cx, outcome.0 + 1, 0, 8);
                    output.emit_derived(&PanicCompletenessOutcome::new(
                        0,
                        vec![
                            PanicCompletenessReason::node_limit(outcome.0, outcome.1),
                            late,
                        ],
                    ))
                }
            }
        }
    }

    fn fake_missing_reason(
        cx: &EvaluationCx<'_, PanicRootInputs>,
        order: u64,
        endpoint_row: u32,
        call_local_id: u32,
    ) -> PanicCompletenessReason {
        let root = cx.root().entity.clone();
        let target = endpoint(root.scope(), endpoint_row);
        PanicCompletenessReason::missing_managed_body(
            order,
            function(99),
            "hostile::missing",
            None,
            vec![PanicCompletenessSemanticStep::new(
                function(98),
                "hostile::caller",
                call_local_id,
                CallKind::DirectCall,
                None,
                Some(function(99)),
                Some(String::from("hostile::missing")),
            )],
            RelationTrace::new(root, target, Vec::new()),
        )
    }

    fn seeded_reporter_registry(mode: SeedSummaryMode) -> AnalysisRegistry<PanicRootInputs> {
        let mut registry = AnalysisRegistry::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        registry
            .register_derived::<PanicCompletenessOutcome>()
            .unwrap();
        registry
            .register_issue::<PanicAnalysisIncompleteIssue>()
            .unwrap();
        registry
            .register_issue_renderer::<PanicAnalysisIncompleteIssue, _>(
                PanicAnalysisIncompleteRenderer,
            )
            .unwrap();
        registry
            .register_evaluation_rule(SeedCompletenessSummary(mode))
            .unwrap();
        registry
            .register_evaluation_rule(ReportPanicIncomplete)
            .unwrap();
        registry
    }

    #[test]
    fn completeness_schemas_are_strict_and_keep_variant_specific_identity() {
        let scope = ArtifactScopeId::new("test.panic.completeness-schema").unwrap();
        let root = endpoint(&scope, 0);
        let target = endpoint(&scope, 1);
        let source_anchor = endpoint(&scope, 2);
        let trace = RelationTrace::new(root, target, Vec::new());
        let source_key = SourceAnchorKey::new("source.rs", 10, 20);
        let semantic_step = PanicCompletenessSemanticStep::new(
            function(1),
            "crate::root",
            4,
            CallKind::DirectCall,
            Some(source_key.clone()),
            Some(function(2)),
            Some(String::from("dependency::missing")),
        );
        let missing = PanicCompletenessReason::missing_managed_body(
            7,
            function(2),
            "dependency::missing",
            Some(PanicCompletenessSource::new(source_anchor, source_key)),
            vec![semantic_step],
            trace,
        );
        let limited = PanicCompletenessReason::node_limit(8, 3);
        let outcome = PanicCompletenessOutcome::new(2, vec![missing.clone(), limited.clone()]);

        assert_eq!(PanicCompletenessOutcome::VERSION, 1);
        assert_eq!(PanicAnalysisIncompleteIssue::VERSION, 1);
        assert!(matches!(
            missing.reason(),
            PanicIncompleteReason::MissingManagedBody {
                path,
                presentation_source: Some(_),
                relation_trace,
                ..
            } if path == "dependency::missing" && relation_trace.relations().is_empty()
        ));
        assert!(matches!(
            limited.reason(),
            PanicIncompleteReason::NodeLimit { limit: 3 }
        ));
        assert_eq!(outcome.expanded_bodies(), 2);
        assert_eq!(outcome.reasons(), [missing.clone(), limited]);
        assert!(!outcome.complete());
        assert!(PanicCompletenessOutcome::new(2, Vec::new()).complete());

        let mut unknown_outer = serde_json::to_value(&outcome).unwrap();
        unknown_outer
            .as_object_mut()
            .unwrap()
            .insert(String::from("future"), serde_json::json!(true));
        assert!(serde_json::from_value::<PanicCompletenessOutcome>(unknown_outer).is_err());

        let mut unknown_trace = serde_json::to_value(&outcome).unwrap();
        unknown_trace["reasons"][0]["reason"]["relation-trace"]["future"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PanicCompletenessOutcome>(unknown_trace).is_err());

        let mut unknown_source = serde_json::to_value(&outcome).unwrap();
        unknown_source["reasons"][0]["reason"]["presentation-source"]["future"] =
            serde_json::json!(true);
        assert!(serde_json::from_value::<PanicCompletenessOutcome>(unknown_source).is_err());
        let mut missing_source_key = serde_json::to_value(&outcome).unwrap();
        missing_source_key["reasons"][0]["reason"]["presentation-source"]
            .as_object_mut()
            .unwrap()
            .remove("key");
        assert!(serde_json::from_value::<PanicCompletenessOutcome>(missing_source_key).is_err());

        let mut unknown_step = serde_json::to_value(&outcome).unwrap();
        unknown_step["reasons"][0]["reason"]["semantic-trace"][0]["future"] =
            serde_json::json!(true);
        assert!(serde_json::from_value::<PanicCompletenessOutcome>(unknown_step).is_err());
        let mut missing_step_field = serde_json::to_value(&outcome).unwrap();
        missing_step_field["reasons"][0]["reason"]["semantic-trace"][0]
            .as_object_mut()
            .unwrap()
            .remove("caller-path");
        assert!(serde_json::from_value::<PanicCompletenessOutcome>(missing_step_field).is_err());

        let issue = PanicAnalysisIncompleteIssue::from_reason(missing);
        let mut unknown_issue = serde_json::to_value(&issue).unwrap();
        unknown_issue
            .as_object_mut()
            .unwrap()
            .insert(String::from("future"), serde_json::json!(true));
        assert!(serde_json::from_value::<PanicAnalysisIncompleteIssue>(unknown_issue).is_err());
        let mut unknown_issue_trace = serde_json::to_value(&issue).unwrap();
        unknown_issue_trace["reason"]["relation-trace"]["future"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<PanicAnalysisIncompleteIssue>(unknown_issue_trace).is_err()
        );
        let mut unknown_issue_source = serde_json::to_value(&issue).unwrap();
        unknown_issue_source["reason"]["presentation-source"]["future"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<PanicAnalysisIncompleteIssue>(unknown_issue_source).is_err()
        );
        let mut unknown_issue_step = serde_json::to_value(&issue).unwrap();
        unknown_issue_step["reason"]["semantic-trace"][0]["future"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<PanicAnalysisIncompleteIssue>(unknown_issue_step).is_err()
        );
    }

    #[test]
    fn completeness_pack_is_an_isolated_two_stage_panic_root_pipeline() {
        fn accepts_only_combined_panic_inputs<P: AnalysisPack<PanicRootInputs>>(_pack: &P) {}

        accepts_only_combined_panic_inputs(&PanicCompletenessPack);
        let mut registry = AnalysisRegistry::<PanicRootInputs>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        registry.install(&PanicCompletenessPack).unwrap();

        let producer = registry
            .evaluation_rules()
            .descriptor(&PassId::new(EMIT_PANIC_COMPLETENESS_RULE).unwrap())
            .unwrap();
        assert_eq!(
            producer.reads().map(SchemaId::as_str).collect::<Vec<_>>(),
            [
                FunctionEntity::ID,
                CallOccurrenceEntity::ID,
                CallSiteEntity::ID,
                CallMacroExpansionEntity::ID,
                CallableEntity::ID,
                SourceAnchorEntity::ID,
            ]
        );
        assert_eq!(
            producer.writes().map(SchemaId::as_str).collect::<Vec<_>>(),
            [PanicCompletenessOutcome::ID]
        );

        let reporter = registry
            .evaluation_rules()
            .descriptor(&PassId::new(REPORT_PANIC_INCOMPLETE_RULE).unwrap())
            .unwrap();
        assert_eq!(
            reporter.reads().map(SchemaId::as_str).collect::<Vec<_>>(),
            [
                FunctionEntity::ID,
                CallOccurrenceEntity::ID,
                CallSiteEntity::ID,
                CallMacroExpansionEntity::ID,
                CallableEntity::ID,
                SourceAnchorEntity::ID,
                PanicCompletenessOutcome::ID,
            ]
        );
        assert_eq!(
            reporter.writes().map(SchemaId::as_str).collect::<Vec<_>>(),
            [PanicAnalysisIncompleteIssue::ID]
        );

        let schedule = registry.evaluation_rules().schedule().unwrap();
        let producer = schedule
            .iter()
            .position(|rule| rule.as_str() == EMIT_PANIC_COMPLETENESS_RULE)
            .unwrap();
        let reporter = schedule
            .iter()
            .position(|rule| rule.as_str() == REPORT_PANIC_INCOMPLETE_RULE)
            .unwrap();
        assert!(producer < reporter);
        assert!(
            registry
                .rendering()
                .has_issue_renderer(&SchemaId::new(PanicAnalysisIncompleteIssue::ID).unwrap())
        );
        assert!(registry.install(&PanicCompletenessPack).is_err());
    }

    #[test]
    fn completeness_renderer_owns_exact_missing_and_budget_presentations() {
        let registry = completeness_registry();
        let artifact = declared_artifact_builder(&registry)
            .finalize(registry.schemas())
            .unwrap();
        let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
        let render_cx = RenderCx::from_validated(view);

        let missing = PanicAnalysisIncompleteIssue::from_reason(
            PanicCompletenessReason::missing_managed_body(
                7,
                function(2),
                "dependency::missing",
                None,
                Vec::new(),
                RelationTrace::new(
                    endpoint(&ArtifactScopeId::for_in_memory(1, 0), 0),
                    endpoint(&ArtifactScopeId::for_in_memory(1, 0), 1),
                    Vec::new(),
                ),
            ),
        );
        let rendered = registry.rendering().render(&missing, &render_cx).unwrap();
        assert_eq!(
            rendered.message,
            "panic analysis could not inspect managed body `dependency::missing`"
        );
        assert_eq!(
            rendered.notes,
            ["results may be incomplete because a reached managed function body was unavailable"]
        );
        assert!(rendered.help.is_empty());
        assert_eq!(rendered.sort_key, ["00000000000000000007"]);
        assert_eq!(
            rendered.data,
            serde_json::json!({
                "kind": "missing-managed-body",
                "function": function(2),
                "path": "dependency::missing",
            })
        );

        let limited =
            PanicAnalysisIncompleteIssue::from_reason(PanicCompletenessReason::node_limit(8, 3));
        let rendered = registry.rendering().render(&limited, &render_cx).unwrap();
        assert_eq!(
            rendered.message,
            "panic analysis reached the configured node limit (3)"
        );
        assert!(rendered.notes.is_empty());
        assert_eq!(
            rendered.help,
            ["increase the analysis node limit to inspect more reachable bodies"]
        );
        assert_eq!(rendered.sort_key, ["00000000000000000008"]);
        assert_eq!(
            rendered.data,
            serde_json::json!({ "kind": "node-limit", "limit": 3 })
        );
    }

    #[test]
    fn legacy_semantic_dedup_ignores_raw_scope_but_preserves_distinct_routes() {
        let first_scope = ArtifactScopeId::for_in_memory(1, 10);
        let replacement_scope = ArtifactScopeId::for_in_memory(1, 11);
        let source_key = SourceAnchorKey::new("same.rs", 4, 8);
        let semantic_step = PanicCompletenessSemanticStep::new(
            function(80),
            "crate::caller",
            3,
            CallKind::DirectCall,
            Some(SourceAnchorKey::new("call.rs", 10, 20)),
            Some(function(81)),
            Some(String::from("crate::missing")),
        );
        let make_reason = |order, scope: &ArtifactScopeId, endpoint_row| {
            PanicCompletenessReason::missing_managed_body(
                order,
                function(81),
                "crate::missing",
                Some(PanicCompletenessSource::new(
                    endpoint(scope, 20),
                    source_key.clone(),
                )),
                vec![semantic_step.clone()],
                RelationTrace::new(
                    endpoint(scope, 0),
                    endpoint(scope, endpoint_row),
                    Vec::new(),
                ),
            )
        };
        let earliest = make_reason(5, &first_scope, 1);
        let replacement = make_reason(7, &replacement_scope, 2);
        assert_ne!(earliest, replacement, "raw provenance must remain exact");
        let earliest_key = LegacyMissingBodyKey::from_reason(earliest.reason()).unwrap();
        assert_eq!(
            earliest_key,
            LegacyMissingBodyKey::from_reason(replacement.reason()).unwrap(),
            "generation-distinct exact witnesses share one legacy semantic identity"
        );

        let mut seen = HashSet::new();
        let mut retained = Vec::new();
        retain_missing_reason(&mut seen, &mut retained, earliest_key, earliest.clone());
        retain_missing_reason(
            &mut seen,
            &mut retained,
            LegacyMissingBodyKey::from_reason(replacement.reason()).unwrap(),
            replacement,
        );
        assert_eq!(retained.as_slice(), std::slice::from_ref(&earliest));
        assert_eq!(retained[0].traversal_order(), 5);
        assert_eq!(retained[0].reason().source(), earliest.reason().source());
        assert_eq!(retained[0].reason().trace(), earliest.reason().trace());

        let distinct = PanicCompletenessReason::missing_managed_body(
            9,
            function(81),
            "crate::missing",
            Some(PanicCompletenessSource::new(
                endpoint(&replacement_scope, 30),
                source_key,
            )),
            vec![PanicCompletenessSemanticStep::new(
                function(80),
                "crate::caller",
                4,
                CallKind::DirectCall,
                Some(SourceAnchorKey::new("call.rs", 10, 20)),
                Some(function(81)),
                Some(String::from("crate::missing")),
            )],
            RelationTrace::new(
                endpoint(&replacement_scope, 0),
                endpoint(&replacement_scope, 3),
                Vec::new(),
            ),
        );
        retain_missing_reason(
            &mut seen,
            &mut retained,
            LegacyMissingBodyKey::from_reason(distinct.reason()).unwrap(),
            distinct.clone(),
        );
        assert_eq!(retained, [earliest, distinct]);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the high-risk fixture keeps route construction and full semantic assertions together"
    )]
    fn managed_missing_body_keeps_presentation_source_and_full_marked_semantic_route() {
        let root = function(10);
        let helper = function(11);
        let missing = function(12);
        with_single_artifact_inputs(
            16,
            Vec::new(),
            |builder| {
                let (root_body, _) = insert_function(builder, root, "crate::root");
                let (helper_body, helper_callable) =
                    insert_function(builder, helper, "crate::helper");
                let missing_callable = insert_callable(builder, missing, "crate::missing");
                let entering_helper =
                    insert_direct_call(builder, &root_body, root, 0, &helper_callable);
                attach_panic_marker_to_call(builder, &entering_helper, 0);
                let entering_missing = insert_call_with_distinct_site_id(
                    builder,
                    &helper_body,
                    helper,
                    1,
                    99,
                    &missing_callable,
                );
                attach_named_call_macros_and_sources(
                    builder,
                    &helper_body,
                    helper,
                    &entering_missing,
                    "outer!",
                    "inner!",
                );
                root
            },
            |registry, workspace, inputs, graph| {
                let [outcome] = inputs.traversal().outcomes() else {
                    panic!("the reached managed declaration must be missing one body");
                };
                assert!(matches!(
                    outcome.kind(),
                    TraversalOutcomeKind::MissingManagedBody { requested, .. }
                        if *requested == missing
                ));
                let terminal = inputs.traversal().followed_calls().last().unwrap();
                assert_eq!(terminal.order().checked_add(1), Some(outcome.order()));
                assert_eq!(terminal.trace(), outcome.trace());
                assert_eq!(terminal.inherited_markers().len(), 1);
                assert_eq!(terminal.occurrence_data().key().local_id(), 1);
                assert_eq!(terminal.call_site_data().key().local_id(), 99);

                let results = evaluate(registry, workspace, &inputs, graph);
                let [summary] = results
                    .derived_rows::<PanicCompletenessOutcome>(registry.schemas())
                    .unwrap()
                    .try_into()
                    .unwrap();
                assert_eq!(summary.data.expanded_bodies(), 2);
                assert!(!summary.data.complete());
                let [reason] = summary.data.reasons() else {
                    panic!("one legacy missing-body identity must be retained");
                };
                assert_eq!(reason.traversal_order(), outcome.order());
                let PanicIncompleteReason::MissingManagedBody {
                    function,
                    path,
                    presentation_source: Some(source),
                    semantic_trace,
                    relation_trace,
                } = reason.reason()
                else {
                    panic!("the summary must retain a missing managed body");
                };
                assert_eq!(*function, missing);
                assert_eq!(path, "crate::missing");
                assert_eq!(source.key(), &SourceAnchorKey::new("nested-file", 10, 20));
                assert_eq!(relation_trace, outcome.trace());
                assert_eq!(semantic_trace.len(), 4);
                assert_eq!(semantic_trace[0].caller(), root);
                assert_eq!(semantic_trace[0].call_local_id(), 0);
                assert_eq!(semantic_trace[0].kind(), CallKind::DirectCall);
                assert_eq!(semantic_trace[0].target(), Some(helper));
                assert_eq!(semantic_trace[1].call_local_id(), 1);
                assert_eq!(semantic_trace[1].kind(), CallKind::MacroExpansion);
                assert_eq!(semantic_trace[1].caller_path(), "crate::helper");
                assert_eq!(semantic_trace[1].target_path(), Some("macro outer!"));
                assert_eq!(
                    semantic_trace[1].source(),
                    Some(&SourceAnchorKey::new("nested-file", 50, 60))
                );
                assert_eq!(semantic_trace[2].call_local_id(), 1);
                assert_eq!(semantic_trace[2].kind(), CallKind::MacroExpansion);
                assert_eq!(semantic_trace[2].caller_path(), "macro outer!");
                assert_eq!(semantic_trace[2].target_path(), Some("macro inner!"));
                assert_eq!(semantic_trace[2].source(), None);
                assert_eq!(semantic_trace[3].call_local_id(), 1);
                assert_eq!(semantic_trace[3].kind(), CallKind::DirectCall);
                assert_eq!(semantic_trace[3].caller_path(), "macro inner!");
                assert_eq!(
                    semantic_trace[3].source(),
                    Some(&SourceAnchorKey::new("nested-file", 30, 40))
                );
                assert_eq!(semantic_trace[3].target(), Some(missing));
                assert_eq!(semantic_trace[3].target_path(), Some("crate::missing"));

                let [issue] = results
                    .issues::<PanicAnalysisIncompleteIssue>(registry.schemas())
                    .unwrap()
                    .try_into()
                    .unwrap();
                assert_eq!(issue.data.traversal_order(), outcome.order());
                assert_eq!(
                    issue.context.source.as_ref(),
                    Some(&source.anchor().as_row())
                );
                assert_eq!(
                    issue.context.endpoint.as_ref(),
                    Some(relation_trace.target())
                );
                assert_eq!(issue.context.trace.as_ref(), Some(relation_trace));
            },
        );
    }

    #[test]
    fn node_budget_zero_exact_exceeded_and_multiple_frontiers_match_legacy() {
        let assert_budget = |budget: usize,
                             target_count: usize,
                             expected_expanded: u64,
                             expected_limit: Option<u64>,
                             expected_frontiers: usize| {
            let root = function(20 + u64::try_from(budget).unwrap());
            with_single_artifact_inputs(
                budget,
                Vec::new(),
                |builder| {
                    let (root_body, _) = insert_function(builder, root, "crate::root");
                    for ordinal in 0..target_count {
                        let local = u64::try_from(ordinal).unwrap();
                        let target = function(30 + local + u64::try_from(budget).unwrap() * 10);
                        let (_, callable) =
                            insert_function(builder, target, &format!("crate::target_{ordinal}"));
                        insert_direct_call(
                            builder,
                            &root_body,
                            root,
                            u32::try_from(ordinal).unwrap(),
                            &callable,
                        );
                    }
                    root
                },
                |registry, workspace, inputs, graph| {
                    assert_eq!(
                        inputs
                            .traversal()
                            .outcomes()
                            .iter()
                            .filter(|outcome| matches!(
                                outcome.kind(),
                                TraversalOutcomeKind::BudgetExceeded { .. }
                            ))
                            .count(),
                        expected_frontiers
                    );
                    let results = evaluate(registry, workspace, &inputs, graph);
                    let [summary] = results
                        .derived_rows::<PanicCompletenessOutcome>(registry.schemas())
                        .unwrap()
                        .try_into()
                        .unwrap();
                    assert_eq!(summary.data.expanded_bodies(), expected_expanded);
                    assert_eq!(
                        summary.data.reasons().len(),
                        usize::from(expected_limit.is_some())
                    );
                    assert_eq!(
                        summary
                            .data
                            .reasons()
                            .first()
                            .and_then(|reason| reason.reason().node_limit_value()),
                        expected_limit
                    );
                    let issues = results
                        .issues::<PanicAnalysisIncompleteIssue>(registry.schemas())
                        .unwrap();
                    assert_eq!(issues.len(), usize::from(expected_limit.is_some()));
                    if let Some(issue) = issues.first() {
                        assert!(issue.context.source.is_none());
                        assert!(issue.context.endpoint.is_none());
                        assert!(issue.context.trace.is_none());
                    }
                },
            );
        };

        assert_budget(0, 0, 0, Some(0), 1);
        assert_budget(1, 1, 1, Some(1), 1);
        assert_budget(2, 1, 2, None, 0);
        assert_budget(1, 2, 1, Some(1), 2);
    }

    #[test]
    fn complete_and_budget_only_traversals_skip_trace_route_indexing() {
        let complete_root = function(60);
        with_single_artifact_inputs(
            8,
            Vec::new(),
            |builder| {
                insert_function(builder, complete_root, "crate::complete_root");
                complete_root
            },
            |registry, workspace, inputs, graph| {
                assert!(inputs.traversal().outcomes().is_empty());

                reset_trace_route_work();
                let results = evaluate(registry, workspace, &inputs, graph);

                let [summary] = results
                    .derived_rows::<PanicCompletenessOutcome>(registry.schemas())
                    .unwrap()
                    .try_into()
                    .unwrap();
                assert!(summary.data.complete());
                assert_eq!(trace_route_work(), TraceRouteWork::default());
            },
        );

        let budget_root = function(61);
        let budget_target = function(62);
        with_single_artifact_inputs(
            1,
            Vec::new(),
            |builder| {
                let (root_body, _) = insert_function(builder, budget_root, "crate::budget_root");
                let (_, target_callable) =
                    insert_function(builder, budget_target, "crate::budget_target");
                insert_direct_call(builder, &root_body, budget_root, 0, &target_callable);
                budget_root
            },
            |registry, workspace, inputs, graph| {
                assert!(matches!(
                    inputs.traversal().outcomes(),
                    [outcome]
                        if matches!(outcome.kind(), TraversalOutcomeKind::BudgetExceeded { .. })
                ));

                reset_trace_route_work();
                let results = evaluate(registry, workspace, &inputs, graph);

                let [summary] = results
                    .derived_rows::<PanicCompletenessOutcome>(registry.schemas())
                    .unwrap()
                    .try_into()
                    .unwrap();
                assert!(matches!(
                    summary.data.reasons(),
                    [reason] if matches!(reason.reason(), PanicIncompleteReason::NodeLimit { .. })
                ));
                assert_eq!(trace_route_work(), TraceRouteWork::default());
            },
        );
    }

    #[test]
    fn cycles_dedup_and_unmanaged_boundaries_still_emit_positive_complete_summaries() {
        let root = function(70);
        with_single_artifact_inputs(
            8,
            Vec::new(),
            |builder| {
                let (root_body, root_callable) = insert_function(builder, root, "crate::root");
                insert_direct_call(builder, &root_body, root, 0, &root_callable);
                root
            },
            |registry, workspace, inputs, graph| {
                assert!(
                    inputs
                        .traversal()
                        .outcomes()
                        .iter()
                        .any(|outcome| matches!(outcome.kind(), TraversalOutcomeKind::Cycle))
                );
                let results = evaluate(registry, workspace, &inputs, graph);
                let [summary] = results
                    .derived_rows::<PanicCompletenessOutcome>(registry.schemas())
                    .unwrap()
                    .try_into()
                    .unwrap();
                assert!(summary.data.complete());
                assert!(
                    results
                        .issues::<PanicAnalysisIncompleteIssue>(registry.schemas())
                        .unwrap()
                        .is_empty()
                );
            },
        );

        let root = function(71);
        let target = function(72);
        with_single_artifact_inputs(
            8,
            Vec::new(),
            |builder| {
                let (root_body, _) = insert_function(builder, root, "crate::root");
                let (_, target_callable) = insert_function(builder, target, "crate::target");
                insert_direct_call(builder, &root_body, root, 0, &target_callable);
                insert_direct_call(builder, &root_body, root, 1, &target_callable);
                root
            },
            |registry, workspace, inputs, graph| {
                assert!(
                    inputs.traversal().outcomes().iter().any(|outcome| matches!(
                        outcome.kind(),
                        TraversalOutcomeKind::Deduplicated
                    ))
                );
                let results = evaluate(registry, workspace, &inputs, graph);
                let [summary] = results
                    .derived_rows::<PanicCompletenessOutcome>(registry.schemas())
                    .unwrap()
                    .try_into()
                    .unwrap();
                assert!(summary.data.complete());
            },
        );

        let root = function(73);
        let unmanaged = function_in(2, 1);
        let unmanaged_artifact = RustcArtifactId::new(2, "b".repeat(32));
        with_single_artifact_inputs(
            8,
            vec![unmanaged_artifact],
            |builder| {
                let (root_body, _) = insert_function(builder, root, "crate::root");
                let callable = insert_callable(builder, unmanaged, "external::declaration");
                insert_direct_call(builder, &root_body, root, 0, &callable);
                root
            },
            |registry, workspace, inputs, graph| {
                assert!(inputs.traversal().outcomes().iter().any(|outcome| matches!(
                    outcome.kind(),
                    TraversalOutcomeKind::UnmanagedStableCrate { .. }
                )));
                let results = evaluate(registry, workspace, &inputs, graph);
                let [summary] = results
                    .derived_rows::<PanicCompletenessOutcome>(registry.schemas())
                    .unwrap()
                    .try_into()
                    .unwrap();
                assert!(summary.data.complete());
            },
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the paired fixtures prove both selectively ignored defining-source outcomes"
    )]
    fn defining_source_gaps_are_selectively_complete_for_panic_analysis() {
        let consumer = function_in(2, 20);
        let unmanaged_artifact = RustcArtifactId::new(2, "c".repeat(32));
        with_single_artifact_inputs(
            8,
            vec![unmanaged_artifact],
            |builder| {
                insert_consumer_function(builder, consumer, 1, "crate::consumer");
                consumer
            },
            |registry, workspace, inputs, graph| {
                assert!(matches!(
                    inputs.traversal().outcomes(),
                    [outcome] if matches!(
                        outcome.kind(),
                        TraversalOutcomeKind::UnmanagedDefiningSource { consumer: found, .. }
                            if *found == consumer
                    )
                ));
                let results = evaluate(registry, workspace, &inputs, graph);
                let [summary] = results
                    .derived_rows::<PanicCompletenessOutcome>(registry.schemas())
                    .unwrap()
                    .try_into()
                    .unwrap();
                assert_eq!(summary.data.expanded_bodies(), 1);
                assert!(summary.data.complete());
                assert!(
                    results
                        .issues::<PanicAnalysisIncompleteIssue>(registry.schemas())
                        .unwrap()
                        .is_empty()
                );
            },
        );

        let registry = completeness_registry();
        let mut root_builder = declared_artifact_builder(&registry);
        insert_consumer_function(&mut root_builder, consumer, 1, "crate::consumer");
        let root_artifact = root_builder.finalize(registry.schemas()).unwrap();
        let dependency_artifact = declared_artifact_builder(&registry)
            .finalize(registry.schemas())
            .unwrap();
        let dependency = RustcArtifactId::new(2, "d".repeat(32));
        let root_generation = ManagedArtifactGeneration::in_memory(1, 0);
        let dependency_generation = ManagedArtifactGeneration::persisted(dependency.clone());
        let root_scope = root_generation.scope().unwrap();
        let dependency_scope = dependency_generation.scope().unwrap();
        let workspace = WorkspaceFactView::compose([
            (
                root_scope,
                ArtifactDbView::open(&root_artifact, registry.schemas()).unwrap(),
            ),
            (
                dependency_scope,
                ArtifactDbView::open(&dependency_artifact, registry.schemas()).unwrap(),
            ),
        ])
        .unwrap();
        let closure = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root_generation, vec![dependency.clone()]),
            [ManagedArtifactManifest::new(
                dependency_generation,
                Vec::new(),
            )],
            [],
        )
        .unwrap();
        let prepared = PreparedCompilerAssertRootBatch::prepare(
            &workspace,
            &closure,
            &PanicConfig::default(),
            &ContractDocOverrides::default(),
            [CompilerAssertRootRequest::new(
                consumer,
                CallAttributionRole::CallSite,
                MarkerProbe::SourceCallsite,
                8,
            )],
        )
        .unwrap()
        .into_roots()
        .pop()
        .unwrap();
        let mut composition = CompositionRelationBuilder::new(
            prepared.root(),
            &workspace,
            registry.composition_relations(),
        )
        .unwrap();
        let emitted = prepared.emit(&mut composition).unwrap();
        let relations = composition.finalize().unwrap();
        let graph = WorkspaceRelationGraph::new(emitted.root(), &workspace, &relations).unwrap();
        let inputs = emitted
            .resolve_panic(&workspace, &graph, registry.composition_relations())
            .unwrap();
        assert!(matches!(
            inputs.traversal().outcomes(),
            [outcome] if matches!(
                outcome.kind(),
                TraversalOutcomeKind::MissingManagedDefiningSource { consumer: found, .. }
                    if *found == consumer
            )
        ));
        let results = evaluate(&registry, &workspace, &inputs, graph);
        let [summary] = results
            .derived_rows::<PanicCompletenessOutcome>(registry.schemas())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(summary.data.expanded_bodies(), 1);
        assert!(summary.data.complete());
        assert!(
            results
                .issues::<PanicAnalysisIncompleteIssue>(registry.schemas())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn hostile_committed_summaries_fail_without_any_partial_issue() {
        for (mode, expected_error) in [
            (
                SeedSummaryMode::Missing,
                "requires exactly one summary row for the active root, found 0",
            ),
            (
                SeedSummaryMode::Duplicate,
                "requires exactly one summary row for the active root, found 2",
            ),
            (
                SeedSummaryMode::WrongProducer,
                "summary has unexpected producer",
            ),
            (
                SeedSummaryMode::AlteredCount,
                "summary disagrees with resolved traversal inputs",
            ),
            (
                SeedSummaryMode::AlteredReason,
                "summary disagrees with resolved traversal inputs",
            ),
            (
                SeedSummaryMode::SemanticDuplicate,
                "duplicate legacy missing-body reasons",
            ),
            (
                SeedSummaryMode::LateAlteredReason,
                "summary disagrees with resolved traversal inputs",
            ),
        ] {
            let root = function(200);
            let registry = seeded_reporter_registry(mode);
            with_registry_single_artifact_inputs(
                &registry,
                0,
                Vec::new(),
                |builder| {
                    insert_function(builder, root, "crate::root");
                    root
                },
                |registry, workspace, inputs, graph| {
                    let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
                    let mut evaluated = EvaluationDb::new();
                    let error = registry
                        .run_workspace_evaluation(
                            &inputs,
                            inputs.root(),
                            &evaluation,
                            &mut evaluated,
                        )
                        .unwrap_err();
                    assert!(error.to_string().contains(expected_error), "{error}");
                    let results = evaluated.finish().unwrap();
                    assert!(
                        results
                            .issues::<PanicAnalysisIncompleteIssue>(registry.schemas())
                            .unwrap()
                            .is_empty()
                    );
                },
            );
        }
    }
}
