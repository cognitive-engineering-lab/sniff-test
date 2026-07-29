//! Safety documentation and justification analysis.
//!
//! For each selected report root, this pass checks that reached public unsafe
//! functions document a `# Safety` contract and that reached unsafe operations
//! — calls and non-call operations alike — have nearby `// SAFETY:`
//! justifications satisfying any named requirements listed by the callee.
//! Operation detection lives in the `thir` submodule, modeled on rustc's own
//! unsafety checker.

mod thir;

use std::collections::{HashMap, HashSet};

use rustc_hir::def::DefKind;
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

use crate::config::SafetyConfig;
use crate::contracts::{
    AmbiguousContractRequirements, ContractDocOverrides, ContractDocSummary, ContractRequirement,
    safety_contract_doc_summary,
};
use crate::effect_tracker::{EffectEvidence, EffectSite};
use crate::namespace::canonical_namespace;

#[derive(Default)]
pub(crate) struct SafetyAnalysis {
    findings_by_owner: HashMap<DefId, Vec<SafetyFinding>>,
    evidence_by_owner: HashMap<DefId, Vec<SafetyEvidence>>,
    probes_by_owner: HashMap<DefId, Vec<SafetyProbe>>,
    analyzed_owners: HashSet<LocalDefId>,
    ambiguous_requirement_names: HashSet<(DefId, DefId, String)>,
    safety_scopes_by_owner: HashMap<DefId, Vec<SafetyEffectGroup>>,
    callable_groups: HashMap<EffectSite, SafetyEffectGroup>,
    next_effect_group: usize,
}

#[derive(Debug, Clone)]
pub(crate) enum SafetyFinding {
    MissingSafetyDocs {
        def_id: DefId,
        span: Span,
    },
    CallMissingJustification {
        site: EffectSite,
        callee: SafetyCallee,
        call_kind: SafetyCallKind,
    },
    CallMissingRequirements {
        site: EffectSite,
        callee: SafetyCallee,
        call_kind: SafetyCallKind,
        missing_requirements: Vec<SafetyRequirement>,
    },
    OpMissingJustification {
        site: EffectSite,
        op: SafetyOpKind,
    },
    AmbiguousObligationName {
        caller: DefId,
        def_id: DefId,
        normalized_name: String,
        requirements: Vec<SafetyRequirement>,
    },
    AmbiguousMarker {
        caller: DefId,
        marker_span: Span,
        effect_spans: Vec<Span>,
    },
}

impl SafetyFinding {
    #[must_use]
    pub(crate) fn owner(&self) -> DefId {
        match *self {
            Self::MissingSafetyDocs { def_id, .. } => def_id,
            Self::CallMissingJustification { site, .. }
            | Self::CallMissingRequirements { site, .. }
            | Self::OpMissingJustification { site, .. } => site.owner,
            Self::AmbiguousObligationName { caller, .. } | Self::AmbiguousMarker { caller, .. } => {
                caller
            }
        }
    }

    #[must_use]
    pub(crate) fn is_root_contract_finding(&self) -> bool {
        match *self {
            Self::MissingSafetyDocs { .. } => true,
            Self::AmbiguousObligationName { caller, def_id, .. } => caller == def_id,
            Self::CallMissingJustification { .. }
            | Self::CallMissingRequirements { .. }
            | Self::OpMissingJustification { .. }
            | Self::AmbiguousMarker { .. } => false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SafetyEffectGroup {
    id: usize,
    pub(crate) span: Span,
}

impl PartialEq for SafetyEffectGroup {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for SafetyEffectGroup {}

impl std::hash::Hash for SafetyEffectGroup {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

#[derive(Clone)]
pub(crate) struct SafetyEvidence {
    effect: EffectEvidence<EffectSite, SafetyEvidenceKind>,
    requirements: Vec<SafetyRequirement>,
    pub(crate) group: SafetyEffectGroup,
}

struct SafetyProbe {
    effect: EffectEvidence<EffectSite, SafetyProbeKind>,
    group: SafetyEffectGroup,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum SafetyProbeKind {
    Call {
        callee: SafetyCallee,
        call_kind: SafetyProbeCallKind,
    },
    Operation(SafetyOpKind),
}

#[derive(Debug, Clone, Copy)]
pub(super) enum SafetyProbeCallKind {
    Unsafe,
    PotentialObligation,
}

#[derive(Debug, Clone, Copy)]
enum SafetyEvidenceKind {
    Call {
        callee: SafetyCallee,
        call_kind: SafetyCallKind,
    },
    Operation(SafetyOpKind),
}

/// Non-call operations that require `unsafe`, mirroring the non-call variants
/// of rustc's `UnsafeOpKind` (`rustc_mir_build/src/check_unsafety.rs`).
///
/// The variant set is pinned to the toolchain in rust-toolchain.toml; diff it
/// against rustc's enum on toolchain bumps. The `unsafe_ops*` fixtures cover
/// one operation per variant as a behavioral canary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SafetyOpKind {
    DerefRawPointer,
    UseOfMutableStatic,
    UseOfExternStatic,
    AccessToUnionField,
    UseOfUnsafeField,
    InitializingLayoutConstrainedType,
    InitializingTypeWithUnsafeField,
    MutationOfLayoutConstrainedField,
    BorrowOfLayoutConstrainedField,
    InlineAssembly,
    UnsafeBinderCast,
}

impl SafetyOpKind {
    #[must_use]
    pub fn label(self) -> &'static str {
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

#[derive(Debug, Clone, Copy)]
pub(crate) enum SafetyCallee {
    Def(DefId),
    FunctionPointer,
}

impl SafetyCallee {
    #[must_use]
    pub fn name(self, tcx: TyCtxt<'_>) -> String {
        match self {
            Self::Def(def_id) => canonical_namespace(tcx, def_id),
            Self::FunctionPointer => String::from("unsafe function pointer"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SafetyCallKind {
    Unsafe,
    Obligation,
}

impl SafetyCallKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unsafe => "unsafe call",
            Self::Obligation => "safety-obligation call",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct SafetyCall {
    callee: SafetyCallee,
    kind: SafetyProbeCallKind,
}

pub(crate) type SafetyRequirement = ContractRequirement;

impl SafetyAnalysis {
    pub(crate) fn findings(&self, owner: DefId) -> &[SafetyFinding] {
        self.findings_by_owner
            .get(&owner)
            .map_or(&[], Vec::as_slice)
    }

    pub(crate) fn evidence(&self, owner: DefId) -> &[SafetyEvidence] {
        self.evidence_by_owner
            .get(&owner)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn push_finding(&mut self, finding: SafetyFinding) {
        self.findings_by_owner
            .entry(finding.owner())
            .or_default()
            .push(finding);
    }

    pub(super) fn push_probe(
        &mut self,
        site: EffectSite,
        details: SafetyProbeKind,
        terminal_marker_spans: Vec<Span>,
        group: SafetyEffectGroup,
    ) {
        self.probes_by_owner
            .entry(site.owner)
            .or_default()
            .push(SafetyProbe {
                effect: EffectEvidence {
                    endpoint: site,
                    terminal_marker_spans,
                    details,
                },
                group,
            });
    }

    pub(crate) fn analyze_owners(
        &mut self,
        tcx: TyCtxt<'_>,
        config: &SafetyConfig,
        owners: impl IntoIterator<Item = LocalDefId>,
    ) {
        for owner in owners {
            if !self.analyzed_owners.insert(owner)
                || !matches!(tcx.def_kind(owner), DefKind::Fn | DefKind::AssocFn)
                || tcx.hir_maybe_body_owned_by(owner).is_none()
                || config.ignores_def(tcx, owner.to_def_id())
            {
                continue;
            }
            collect_missing_safety_docs(tcx, owner, config, self);
            thir::collect_body_evidence(tcx, owner, config, self);
        }
        for owner in self.probes_by_owner.keys().copied().collect::<Vec<_>>() {
            self.resolve_owner_probes(tcx, owner, config);
        }
    }

    /// Resolves a safe obligation whose concrete target is visible only in a
    /// reachability callable edge; THIR sees the call operand as an erased type.
    pub(crate) fn callable_obligation_evidence(
        &mut self,
        tcx: TyCtxt<'_>,
        config: &SafetyConfig,
        site: EffectSite,
        def_id: DefId,
    ) -> Option<SafetyEvidence> {
        if fn_def_is_unsafe(tcx, def_id) || config.ignores_def(tcx, def_id) {
            return None;
        }
        let summary = safety_doc_summary(tcx, def_id, &config.documentation_overrides);
        if !summary.has_docs {
            return None;
        }
        self.push_ambiguous_requirement_names(site.owner, def_id, summary.ambiguous_requirements);
        let (group, terminal_marker_spans) = self.effect_context_for_site(site);
        Some(SafetyEvidence {
            effect: EffectEvidence {
                endpoint: site,
                terminal_marker_spans,
                details: SafetyEvidenceKind::Call {
                    callee: SafetyCallee::Def(def_id),
                    call_kind: SafetyCallKind::Obligation,
                },
            },
            requirements: summary.requirements,
            group,
        })
    }

    /// Adds target-specific contract evidence beside an erased unsafe-call
    /// probe while retaining the original source marker group.
    pub(crate) fn resolved_unsafe_call_evidence(
        &mut self,
        tcx: TyCtxt<'_>,
        config: &SafetyConfig,
        erased: &SafetyEvidence,
        def_id: DefId,
    ) -> Option<SafetyEvidence> {
        if !fn_def_is_unsafe(tcx, def_id) || config.ignores_def(tcx, def_id) {
            return None;
        }
        let summary = safety_doc_summary(tcx, def_id, &config.documentation_overrides);
        if !summary.has_docs {
            return None;
        }
        self.push_ambiguous_requirement_names(
            erased.site().owner,
            def_id,
            summary.ambiguous_requirements,
        );
        Some(SafetyEvidence {
            effect: EffectEvidence {
                endpoint: erased.site(),
                terminal_marker_spans: erased.terminal_marker_spans().to_vec(),
                details: SafetyEvidenceKind::Call {
                    callee: SafetyCallee::Def(def_id),
                    call_kind: SafetyCallKind::Unsafe,
                },
            },
            requirements: summary.requirements,
            group: erased.group,
        })
    }

    fn resolve_owner_probes(&mut self, tcx: TyCtxt<'_>, owner: DefId, config: &SafetyConfig) {
        for probe in self.probes_by_owner.remove(&owner).unwrap_or_default() {
            let (details, requirements) = match probe.effect.details {
                SafetyProbeKind::Operation(op) => (SafetyEvidenceKind::Operation(op), Vec::new()),
                SafetyProbeKind::Call { callee, call_kind } => {
                    let summary = match callee {
                        SafetyCallee::Def(def_id) => {
                            let summary =
                                safety_doc_summary(tcx, def_id, &config.documentation_overrides);
                            self.push_ambiguous_requirement_names(
                                owner,
                                def_id,
                                summary.ambiguous_requirements.clone(),
                            );
                            summary
                        }
                        SafetyCallee::FunctionPointer => ContractDocSummary::default(),
                    };
                    let call_kind = match call_kind {
                        SafetyProbeCallKind::Unsafe => {
                            if let SafetyCallee::Def(def_id) = callee
                                && config.trusts_safety_boundary_def(tcx, def_id)
                                && !summary.has_docs
                            {
                                continue;
                            }
                            SafetyCallKind::Unsafe
                        }
                        SafetyProbeCallKind::PotentialObligation => {
                            if !matches!(callee, SafetyCallee::Def(_)) || !summary.has_docs {
                                continue;
                            }
                            SafetyCallKind::Obligation
                        }
                    };
                    (
                        SafetyEvidenceKind::Call { callee, call_kind },
                        summary.requirements,
                    )
                }
            };
            self.evidence_by_owner
                .entry(owner)
                .or_default()
                .push(SafetyEvidence {
                    effect: EffectEvidence {
                        endpoint: probe.effect.endpoint,
                        terminal_marker_spans: probe.effect.terminal_marker_spans,
                        details,
                    },
                    requirements,
                    group: probe.group,
                });
        }
    }

    fn push_ambiguous_requirement_names(
        &mut self,
        caller: DefId,
        def_id: DefId,
        ambiguous_requirements: Vec<AmbiguousContractRequirements>,
    ) {
        for ambiguous in ambiguous_requirements {
            if !self.ambiguous_requirement_names.insert((
                caller,
                def_id,
                ambiguous.normalized_name.clone(),
            )) {
                continue;
            }
            self.push_finding(SafetyFinding::AmbiguousObligationName {
                caller,
                def_id,
                normalized_name: ambiguous.normalized_name,
                requirements: ambiguous.requirements,
            });
        }
    }

    fn effect_context_for_site(&mut self, site: EffectSite) -> (SafetyEffectGroup, Vec<Span>) {
        let containing = self
            .safety_scopes_by_owner
            .get(&site.owner)
            .into_iter()
            .flatten()
            .filter(|group| crate::source_markers::span_contains(group.span, site.span))
            .copied()
            .collect::<Vec<_>>();
        if let Some(group) = containing.last().copied() {
            let marker_spans = containing.into_iter().map(|group| group.span).collect();
            (group, marker_spans)
        } else {
            let group = if let Some(group) = self.callable_groups.get(&site) {
                *group
            } else {
                let group = self.new_effect_group(site.span);
                self.callable_groups.insert(site, group);
                group
            };
            (group, vec![site.span])
        }
    }

    fn inherit_effect_scopes(&mut self, owner: DefId, inherited: &[SafetyEffectGroup]) {
        let groups = self.safety_scopes_by_owner.entry(owner).or_default();
        for group in inherited {
            if !groups.contains(group) {
                groups.push(*group);
            }
        }
    }

    fn new_safety_scope(&mut self, owner: DefId, span: Span) -> SafetyEffectGroup {
        let group = self.new_effect_group(span);
        self.safety_scopes_by_owner
            .entry(owner)
            .or_default()
            .push(group);
        group
    }

    fn new_effect_group(&mut self, span: Span) -> SafetyEffectGroup {
        let group = SafetyEffectGroup {
            id: self.next_effect_group,
            span,
        };
        self.next_effect_group += 1;
        group
    }
}

impl SafetyEvidence {
    pub(crate) fn requirements(&self) -> &[SafetyRequirement] {
        &self.requirements
    }

    pub(crate) fn terminal_marker_spans(&self) -> &[Span] {
        &self.effect.terminal_marker_spans
    }

    pub(crate) fn site(&self) -> EffectSite {
        self.effect.endpoint
    }

    pub(crate) fn is_function_pointer_call(&self) -> bool {
        matches!(
            self.effect.details,
            SafetyEvidenceKind::Call {
                callee: SafetyCallee::FunctionPointer,
                ..
            }
        )
    }

    pub(crate) fn finding(&self, missing_requirements: Vec<SafetyRequirement>) -> SafetyFinding {
        let site = self.effect.endpoint;
        match self.effect.details {
            SafetyEvidenceKind::Call { callee, call_kind } if missing_requirements.is_empty() => {
                SafetyFinding::CallMissingJustification {
                    site,
                    callee,
                    call_kind,
                }
            }
            SafetyEvidenceKind::Call { callee, call_kind } => {
                SafetyFinding::CallMissingRequirements {
                    site,
                    callee,
                    call_kind,
                    missing_requirements,
                }
            }
            SafetyEvidenceKind::Operation(op) => {
                debug_assert!(missing_requirements.is_empty());
                SafetyFinding::OpMissingJustification { site, op }
            }
        }
    }
}

#[must_use]
pub(crate) fn has_safety_docs(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    overrides: &ContractDocOverrides,
) -> bool {
    safety_doc_summary(tcx, def_id, overrides).has_docs
}

fn collect_missing_safety_docs(
    tcx: TyCtxt<'_>,
    owner: LocalDefId,
    config: &SafetyConfig,
    analysis: &mut SafetyAnalysis,
) {
    let def_id = owner.to_def_id();
    // Effective visibility, not declared: only functions callers outside the
    // crate can actually reach — directly or through re-exports — owe them
    // `# Safety` docs.
    if !tcx.effective_visibilities(()).is_exported(owner)
        || !fn_def_is_unsafe(tcx, def_id)
        || config.ignores_def(tcx, def_id)
    {
        return;
    }

    let summary = safety_doc_summary(tcx, def_id, &config.documentation_overrides);
    if summary.has_docs {
        analysis.push_ambiguous_requirement_names(def_id, def_id, summary.ambiguous_requirements);
    } else {
        analysis.push_finding(SafetyFinding::MissingSafetyDocs {
            def_id,
            span: tcx.def_span(def_id),
        });
    }
}

#[must_use]
pub(crate) fn fn_def_is_unsafe(tcx: TyCtxt<'_>, def_id: DefId) -> bool {
    matches!(tcx.def_kind(def_id), DefKind::Fn | DefKind::AssocFn)
        && tcx
            .fn_sig(def_id)
            .instantiate_identity()
            .skip_binder()
            .safety()
            .is_unsafe()
}

pub(super) type SafetyDocSummary = ContractDocSummary;

pub(super) fn safety_doc_summary(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    overrides: &ContractDocOverrides,
) -> SafetyDocSummary {
    safety_contract_doc_summary(tcx, def_id, overrides)
}
