//! Safety documentation and justification analysis.
//!
//! This pass checks that public unsafe functions document a `# Safety`
//! contract and that unsafe operations — calls and non-call operations alike —
//! have nearby `// SAFETY:` justifications satisfying any named requirements
//! listed by the callee. Operation detection lives in the `thir` submodule,
//! modeled on rustc's own unsafety checker.

mod thir;

use std::collections::HashSet;

use rustc_hir::def::DefKind;
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

use crate::config::{ContractDocOverrides, SafetyConfig};
use crate::contracts::{
    AmbiguousContractRequirements, ContractDocSummary, ContractKind, ContractRequirement,
    contract_doc_summary, normalize_requirement_name, satisfied_requirement_names,
};
use crate::namespace::canonical_namespace;
use crate::source_markers::SafetySatisfaction;

#[derive(Debug, Default)]
pub struct SafetyAnalysis {
    pub findings: Vec<SafetyFinding>,
    ambiguous_requirement_names: HashSet<(DefId, String)>,
}

#[derive(Debug, Clone)]
pub enum SafetyFinding {
    MissingSafetyDocs {
        def_id: DefId,
        span: Span,
    },
    CallMissingJustification {
        caller: DefId,
        callee: SafetyCallee,
        call_kind: SafetyCallKind,
        span: Span,
    },
    CallMissingRequirements {
        caller: DefId,
        callee: SafetyCallee,
        call_kind: SafetyCallKind,
        span: Span,
        missing_requirements: Vec<SafetyRequirement>,
    },
    OpMissingJustification {
        caller: DefId,
        op: SafetyOpKind,
        span: Span,
    },
    AmbiguousObligationName {
        def_id: DefId,
        normalized_name: String,
        requirements: Vec<SafetyRequirement>,
    },
}

/// Non-call operations that require `unsafe`, mirroring the non-call variants
/// of rustc's `UnsafeOpKind` (`rustc_mir_build/src/check_unsafety.rs`).
///
/// The variant set is pinned to the toolchain in rust-toolchain.toml; diff it
/// against rustc's enum on toolchain bumps. The `unsafe_ops*` fixtures cover
/// one operation per variant as a behavioral canary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyOpKind {
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
pub enum SafetyCallee {
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
pub enum SafetyCallKind {
    Unsafe,
    ConfiguredObligation,
}

impl SafetyCallKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unsafe => "unsafe call",
            Self::ConfiguredObligation => "safety-obligation call",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SafetyCall {
    callee: SafetyCallee,
    kind: SafetyCallKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyRequirement {
    pub name: String,
    pub condition: String,
    pub span: Span,
}

impl SafetyRequirement {
    pub(crate) fn render(&self) -> String {
        if self.condition.is_empty() {
            self.name.clone()
        } else {
            format!("{}: {}", self.name, self.condition)
        }
    }
}

#[derive(Debug, Clone)]
pub struct AmbiguousSafetyRequirements {
    pub normalized_name: String,
    pub requirements: Vec<SafetyRequirement>,
}

impl From<ContractRequirement> for SafetyRequirement {
    fn from(requirement: ContractRequirement) -> Self {
        Self {
            name: requirement.name,
            condition: requirement.condition,
            span: requirement.span,
        }
    }
}

impl From<AmbiguousContractRequirements> for AmbiguousSafetyRequirements {
    fn from(requirements: AmbiguousContractRequirements) -> Self {
        Self {
            normalized_name: requirements.normalized_name,
            requirements: requirements
                .requirements
                .into_iter()
                .map(SafetyRequirement::from)
                .collect(),
        }
    }
}

impl SafetyAnalysis {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    fn push_ambiguous_requirement_names(
        &mut self,
        tcx: TyCtxt<'_>,
        def_id: DefId,
        overrides: &ContractDocOverrides,
    ) {
        for ambiguous in safety_doc_summary(tcx, def_id, overrides).ambiguous_requirements {
            if !self
                .ambiguous_requirement_names
                .insert((def_id, ambiguous.normalized_name.clone()))
            {
                continue;
            }
            self.findings.push(SafetyFinding::AmbiguousObligationName {
                def_id,
                normalized_name: ambiguous.normalized_name,
                requirements: ambiguous.requirements,
            });
        }
    }
}

#[must_use]
pub fn analyze_safety(tcx: TyCtxt<'_>, config: &SafetyConfig) -> SafetyAnalysis {
    let mut analysis = SafetyAnalysis::default();

    for owner in tcx.hir_body_owners() {
        if matches!(tcx.def_kind(owner), DefKind::Fn | DefKind::AssocFn) {
            collect_missing_safety_docs(tcx, owner, config, &mut analysis);
        }
        // Closures and inline consts are visited with their enclosing body so
        // justification scopes flow into them lexically; every other body
        // owner — including const and static initializers — starts here.
        if tcx.is_typeck_child(owner.to_def_id()) || config.ignores_def(tcx, owner.to_def_id()) {
            continue;
        }
        thir::collect_body_findings(tcx, owner, config, &mut analysis);
    }

    analysis
}

#[must_use]
pub fn has_safety_docs(tcx: TyCtxt<'_>, def_id: DefId, overrides: &ContractDocOverrides) -> bool {
    safety_doc_summary(tcx, def_id, overrides).has_docs
}

#[must_use]
pub fn safety_requirements(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    overrides: &ContractDocOverrides,
) -> Vec<SafetyRequirement> {
    safety_doc_summary(tcx, def_id, overrides).requirements
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
        analysis.push_ambiguous_requirement_names(tcx, def_id, &config.documentation_overrides);
    } else {
        analysis.findings.push(SafetyFinding::MissingSafetyDocs {
            def_id,
            span: tcx.def_span(def_id),
        });
    }
}

#[must_use]
pub fn fn_def_is_unsafe(tcx: TyCtxt<'_>, def_id: DefId) -> bool {
    matches!(tcx.def_kind(def_id), DefKind::Fn | DefKind::AssocFn)
        && tcx
            .fn_sig(def_id)
            .instantiate_identity()
            .skip_binder()
            .safety()
            .is_unsafe()
}

#[derive(Debug, Default)]
pub(super) struct SafetyDocSummary {
    pub(super) has_docs: bool,
    pub(super) requirements: Vec<SafetyRequirement>,
    pub(super) ambiguous_requirements: Vec<AmbiguousSafetyRequirements>,
}

impl From<ContractDocSummary> for SafetyDocSummary {
    fn from(summary: ContractDocSummary) -> Self {
        Self {
            has_docs: summary.has_docs,
            requirements: summary
                .requirements
                .into_iter()
                .map(SafetyRequirement::from)
                .collect(),
            ambiguous_requirements: summary
                .ambiguous_requirements
                .into_iter()
                .map(AmbiguousSafetyRequirements::from)
                .collect(),
        }
    }
}

pub(super) fn safety_doc_summary(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    overrides: &ContractDocOverrides,
) -> SafetyDocSummary {
    contract_doc_summary(tcx, def_id, ContractKind::Safety, overrides).into()
}

#[cfg(test)]
fn line_has_safety_heading(line: &str) -> bool {
    crate::contracts::line_has_contract_heading(line, ContractKind::Safety)
}

#[cfg(test)]
fn parse_safety_doc_lines<'a>(lines: impl IntoIterator<Item = &'a str>) -> SafetyDocSummary {
    crate::contracts::parse_contract_doc_lines(lines, ContractKind::Safety).into()
}

fn missing_safety_requirements(
    requirements: &[SafetyRequirement],
    satisfactions: &[SafetySatisfaction],
) -> Vec<SafetyRequirement> {
    let satisfied_requirements = satisfied_requirement_names(
        satisfactions
            .iter()
            .map(|satisfaction| (satisfaction.requirement.as_deref(), &*satisfaction.reason)),
    );
    requirements
        .iter()
        .filter(|requirement| {
            let normalized_name = normalize_requirement_name(&requirement.name);
            !satisfied_requirements.contains(&normalized_name)
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        SafetyRequirement, line_has_safety_heading, missing_safety_requirements,
        parse_safety_doc_lines,
    };
    use crate::source_markers::SafetySatisfaction;
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

    #[test]
    fn all_named_safety_requirements_must_be_satisfied() {
        let requirements = [
            SafetyRequirement {
                name: String::from("valid_ptr"),
                condition: String::from("pointer must be non-null"),
                span: DUMMY_SP,
            },
            SafetyRequirement {
                name: String::from("initialized"),
                condition: String::from("pointer must be initialized"),
                span: DUMMY_SP,
            },
        ];
        let satisfactions = [SafetySatisfaction {
            requirement: Some(String::from("valid ptr")),
            reason: String::from("NonNull proves this"),
        }];

        assert_eq!(
            missing_safety_requirements(&requirements, &satisfactions),
            [SafetyRequirement {
                name: String::from("initialized"),
                condition: String::from("pointer must be initialized"),
                span: DUMMY_SP,
            }]
        );
    }

    #[test]
    fn ambiguous_safety_requirement_names_do_not_change_requirement_matching() {
        let requirements = [
            SafetyRequirement {
                name: String::from("valid_ptr"),
                condition: String::from("pointer must be non-null"),
                span: DUMMY_SP,
            },
            SafetyRequirement {
                name: String::from("valid ptr"),
                condition: String::from("pointer must be initialized"),
                span: DUMMY_SP,
            },
        ];
        let satisfactions = [SafetySatisfaction {
            requirement: Some(String::from("valid_ptr")),
            reason: String::from("checked"),
        }];

        assert!(missing_safety_requirements(&requirements, &satisfactions).is_empty());
    }
}
