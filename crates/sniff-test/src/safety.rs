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

use crate::config::{ContractDocOverrides, SafetyConfig};
use crate::contracts::{ContractDocSummary, ContractRequirement, EffectKind, contract_doc_summary};
use crate::effect_tracker::EffectSite;
use crate::namespace::canonical_namespace;
use crate::source_markers::MarkerBlockKey;

#[derive(Debug, Default)]
pub(crate) struct SafetyAnalysis {
    findings_by_owner: HashMap<DefId, Vec<SafetyFinding>>,
    analyzed_owners: HashSet<LocalDefId>,
    ambiguous_requirement_names: HashSet<(DefId, DefId, String)>,
    marker_claims_by_owner: HashMap<DefId, Vec<SafetyMarkerClaim>>,
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
    pub(crate) fn with_missing_requirements(
        mut self,
        requirements: Vec<SafetyRequirement>,
    ) -> Self {
        if let Self::CallMissingRequirements {
            missing_requirements,
            ..
        } = &mut self
        {
            *missing_requirements = requirements;
        }
        self
    }

    #[must_use]
    pub(crate) fn effect_site(&self) -> Option<EffectSite> {
        match *self {
            Self::CallMissingJustification { site, .. }
            | Self::CallMissingRequirements { site, .. }
            | Self::OpMissingJustification { site, .. } => Some(site),
            Self::MissingSafetyDocs { .. }
            | Self::AmbiguousObligationName { .. }
            | Self::AmbiguousMarker { .. } => None,
        }
    }

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

    #[must_use]
    pub(crate) fn missing_requirements(&self) -> &[SafetyRequirement] {
        match self {
            Self::CallMissingRequirements {
                missing_requirements,
                ..
            } => missing_requirements,
            Self::MissingSafetyDocs { .. }
            | Self::CallMissingJustification { .. }
            | Self::OpMissingJustification { .. }
            | Self::AmbiguousObligationName { .. }
            | Self::AmbiguousMarker { .. } => &[],
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SafetyEffectGroup {
    id: usize,
    span: Span,
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

#[derive(Debug)]
struct SafetyMarkerClaim {
    key: MarkerBlockKey,
    marker_span: Span,
    group: SafetyEffectGroup,
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
struct SafetyCall {
    callee: SafetyCallee,
    kind: SafetyCallKind,
}

pub(crate) type SafetyRequirement = ContractRequirement;

impl SafetyAnalysis {
    pub(crate) fn findings(&self, owner: DefId) -> &[SafetyFinding] {
        self.findings_by_owner
            .get(&owner)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn push_finding(&mut self, finding: SafetyFinding) {
        self.findings_by_owner
            .entry(finding.owner())
            .or_default()
            .push(finding);
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
            thir::collect_body_findings(tcx, owner, config, self);
        }
    }

    fn push_ambiguous_requirement_names(
        &mut self,
        tcx: TyCtxt<'_>,
        caller: DefId,
        def_id: DefId,
        overrides: &ContractDocOverrides,
    ) {
        for ambiguous in safety_doc_summary(tcx, def_id, overrides).ambiguous_requirements {
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

    fn new_effect_group(&mut self, span: Span) -> SafetyEffectGroup {
        let group = SafetyEffectGroup {
            id: self.next_effect_group,
            span,
        };
        self.next_effect_group += 1;
        group
    }

    fn claim_marker(
        &mut self,
        owner: DefId,
        key: MarkerBlockKey,
        marker_span: Span,
        group: SafetyEffectGroup,
    ) {
        self.marker_claims_by_owner
            .entry(owner)
            .or_default()
            .push(SafetyMarkerClaim {
                key,
                marker_span,
                group,
            });
    }

    pub(crate) fn ambiguous_marker_findings(
        &self,
        caller: DefId,
        owners: impl IntoIterator<Item = DefId>,
    ) -> Vec<SafetyFinding> {
        crate::effect_tracker::ambiguous_marker_uses(
            owners
                .into_iter()
                .filter_map(|owner| self.marker_claims_by_owner.get(&owner))
                .flatten()
                .map(|claim| (claim.key, claim.marker_span, claim.group)),
        )
        .into_iter()
        .map(|marker_use| SafetyFinding::AmbiguousMarker {
            caller,
            marker_span: marker_use.marker_span,
            effect_spans: marker_use
                .groups
                .into_iter()
                .map(|group| group.span)
                .collect(),
        })
        .collect()
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

    if has_safety_docs(tcx, def_id, &config.documentation_overrides) {
        analysis.push_ambiguous_requirement_names(
            tcx,
            def_id,
            def_id,
            &config.documentation_overrides,
        );
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
    contract_doc_summary(tcx, def_id, EffectKind::Safety, overrides)
}

#[cfg(test)]
fn line_has_safety_heading(line: &str) -> bool {
    crate::contracts::line_has_contract_heading(line, EffectKind::Safety)
}

#[cfg(test)]
fn parse_safety_doc_lines<'a>(lines: impl IntoIterator<Item = &'a str>) -> SafetyDocSummary {
    crate::contracts::parse_contract_doc_lines(lines, EffectKind::Safety)
}

#[cfg(test)]
mod tests {
    use super::{SafetyRequirement, line_has_safety_heading, parse_safety_doc_lines};
    use rustc_span::DUMMY_SP;

    #[test]
    fn safety_doc_headings_match_supported_styles() {
        assert!(line_has_safety_heading("# Safety"));
        assert!(line_has_safety_heading("   ## SAFETY   "));
        assert!(line_has_safety_heading("### Safety:"));
    }

    #[test]
    fn safety_doc_headings_do_not_match_arbitrary_text() {
        assert!(!line_has_safety_heading("Safety: no heading"));
        assert!(!line_has_safety_heading("#Safety"));
        assert!(!line_has_safety_heading("# Panics"));
        assert!(!line_has_safety_heading("# Safety notes"));
    }

    #[test]
    fn safety_doc_requirements_are_named_bullets_under_safety() {
        let summary = parse_safety_doc_lines([
            "# Safety",
            "",
            "The caller must satisfy all listed requirements.",
            "",
            "Requirements:",
            "",
            "- valid_ptr: pointer must be non-null",
            "* initialized: pointer must reference initialized memory",
            "- aligned:",
            "# Panics",
            "- ignored: this is outside the safety section",
        ]);

        assert!(summary.has_docs);
        assert_eq!(
            summary.requirements,
            [
                SafetyRequirement {
                    name: String::from("valid_ptr"),
                    condition: String::from("pointer must be non-null"),
                    span: DUMMY_SP,
                },
                SafetyRequirement {
                    name: String::from("initialized"),
                    condition: String::from("pointer must reference initialized memory"),
                    span: DUMMY_SP,
                },
                SafetyRequirement {
                    name: String::from("aligned"),
                    condition: String::new(),
                    span: DUMMY_SP,
                },
            ]
        );
    }
}
