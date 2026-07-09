//! Safety documentation and justification analysis.
//!
//! This pass checks that public unsafe functions document a `# Safety`
//! contract and that unsafe operations — calls and non-call operations alike —
//! have nearby `// SAFETY:` justifications satisfying any named requirements
//! listed by the callee. Operation detection lives in the [`thir`] submodule,
//! modeled on rustc's own unsafety checker.

mod thir;

use std::collections::HashSet;

use rustc_hir::def::DefKind;
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

use crate::config::{LintLevel, SafetyConfig, SafetyLintConfig};
use crate::contracts::{
    ContractDocSummary, ContractKind, ContractRequirement, contract_doc_summary,
    normalize_requirement_name,
};
use crate::namespace::canonical_namespace;
use crate::source_markers::SafetySatisfaction;

#[derive(Debug, Default)]
pub struct SafetyAnalysis {
    pub findings: Vec<SafetyFinding>,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyFindingKind {
    MissingSafetyDocs,
    UnsafeCallMissingJustification,
    UnsafeCallMissingRequirements,
    UnsafeOpMissingJustification,
    SafetyObligationMissingJustification,
    SafetyObligationMissingRequirements,
}

/// Non-call operations that require `unsafe`, mirroring the non-call variants
/// of rustc's `UnsafeOpKind` (rustc_mir_build/src/check_unsafety.rs).
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

#[must_use]
pub fn safety_op_label(op: SafetyOpKind) -> &'static str {
    match op {
        SafetyOpKind::DerefRawPointer => "raw pointer dereference",
        SafetyOpKind::UseOfMutableStatic => "mutable static access",
        SafetyOpKind::UseOfExternStatic => "extern static access",
        SafetyOpKind::AccessToUnionField => "union field access",
        SafetyOpKind::UseOfUnsafeField => "unsafe field access",
        SafetyOpKind::InitializingLayoutConstrainedType => {
            "layout-constrained type initialization"
        }
        SafetyOpKind::InitializingTypeWithUnsafeField => "unsafe field initialization",
        SafetyOpKind::MutationOfLayoutConstrainedField => "layout-constrained field mutation",
        SafetyOpKind::BorrowOfLayoutConstrainedField => "layout-constrained field borrow",
        SafetyOpKind::InlineAssembly => "inline assembly",
        SafetyOpKind::UnsafeBinderCast => "unsafe binder cast",
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SafetyCallee {
    Def(DefId),
    FunctionPointer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyCallKind {
    Unsafe,
    ConfiguredObligation,
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
}

impl From<ContractRequirement> for SafetyRequirement {
    fn from(requirement: ContractRequirement) -> Self {
        Self {
            name: requirement.name,
            condition: requirement.condition,
        }
    }
}

impl SafetyAnalysis {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    #[must_use]
    pub fn has_denied_findings(&self, lints: SafetyLintConfig) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.kind().lint_level(lints) == LintLevel::Deny)
    }
}

impl SafetyFinding {
    #[must_use]
    pub fn kind(&self) -> SafetyFindingKind {
        match self {
            Self::MissingSafetyDocs { .. } => SafetyFindingKind::MissingSafetyDocs,
            Self::CallMissingJustification { call_kind, .. } => match call_kind {
                SafetyCallKind::Unsafe => SafetyFindingKind::UnsafeCallMissingJustification,
                SafetyCallKind::ConfiguredObligation => {
                    SafetyFindingKind::SafetyObligationMissingJustification
                }
            },
            Self::CallMissingRequirements { call_kind, .. } => match call_kind {
                SafetyCallKind::Unsafe => SafetyFindingKind::UnsafeCallMissingRequirements,
                SafetyCallKind::ConfiguredObligation => {
                    SafetyFindingKind::SafetyObligationMissingRequirements
                }
            },
            Self::OpMissingJustification { .. } => SafetyFindingKind::UnsafeOpMissingJustification,
        }
    }
}

impl SafetyFindingKind {
    #[must_use]
    pub fn lint_level(self, lints: SafetyLintConfig) -> LintLevel {
        match self {
            Self::MissingSafetyDocs => lints.missing_safety_docs,
            Self::UnsafeCallMissingJustification => lints.unsafe_call_missing_justification,
            Self::UnsafeCallMissingRequirements => lints.unsafe_call_missing_requirements,
            Self::UnsafeOpMissingJustification => lints.unsafe_op_missing_justification,
            Self::SafetyObligationMissingJustification => {
                lints.safety_obligation_missing_justification
            }
            Self::SafetyObligationMissingRequirements => {
                lints.safety_obligation_missing_requirements
            }
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
pub fn has_safety_docs(tcx: TyCtxt<'_>, def_id: DefId) -> bool {
    safety_doc_summary(tcx, def_id).has_docs
}

#[must_use]
pub fn safety_requirements(tcx: TyCtxt<'_>, def_id: DefId) -> Vec<SafetyRequirement> {
    safety_doc_summary(tcx, def_id).requirements
}

#[must_use]
pub fn safety_callee_name(tcx: TyCtxt<'_>, callee: SafetyCallee) -> String {
    match callee {
        SafetyCallee::Def(def_id) => canonical_namespace(tcx, def_id),
        SafetyCallee::FunctionPointer => String::from("unsafe function pointer"),
    }
}

#[must_use]
pub fn safety_call_label(kind: SafetyCallKind) -> &'static str {
    match kind {
        SafetyCallKind::Unsafe => "unsafe call",
        SafetyCallKind::ConfiguredObligation => "safety-obligation call",
    }
}

fn collect_missing_safety_docs(
    tcx: TyCtxt<'_>,
    owner: LocalDefId,
    config: &SafetyConfig,
    analysis: &mut SafetyAnalysis,
) {
    let def_id = owner.to_def_id();
    if !tcx.visibility(owner).is_public()
        || !fn_def_is_unsafe(tcx, def_id)
        || config.ignores_def(tcx, def_id)
    {
        return;
    }

    if !has_safety_docs(tcx, def_id) {
        analysis.findings.push(SafetyFinding::MissingSafetyDocs {
            def_id,
            span: tcx.def_span(def_id),
        });
    }
}

fn fn_def_is_unsafe(tcx: TyCtxt<'_>, def_id: DefId) -> bool {
    matches!(tcx.def_kind(def_id), DefKind::Fn | DefKind::AssocFn)
        && tcx
            .fn_sig(def_id)
            .instantiate_identity()
            .skip_binder()
            .safety()
            .is_unsafe()
}

#[derive(Debug, Default)]
struct SafetyDocSummary {
    has_docs: bool,
    requirements: Vec<SafetyRequirement>,
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
        }
    }
}

fn safety_doc_summary(tcx: TyCtxt<'_>, def_id: DefId) -> SafetyDocSummary {
    contract_doc_summary(tcx, def_id, ContractKind::Safety).into()
}

#[cfg(test)]
fn line_has_safety_heading(line: &str) -> bool {
    crate::contracts::line_has_contract_heading(line, ContractKind::Safety)
}

#[cfg(test)]
fn parse_safety_doc_lines<'a>(lines: impl IntoIterator<Item = &'a str>) -> SafetyDocSummary {
    crate::contracts::parse_contract_doc_lines(lines, ContractKind::Safety).into()
}

pub(crate) fn render_safety_requirement(requirement: &SafetyRequirement) -> String {
    if requirement.condition.is_empty() {
        requirement.name.clone()
    } else {
        format!("{}: {}", requirement.name, requirement.condition)
    }
}

fn missing_safety_requirements(
    requirements: &[SafetyRequirement],
    satisfactions: &[SafetySatisfaction],
) -> Vec<SafetyRequirement> {
    let satisfied_requirements = satisfactions
        .iter()
        .filter(|satisfaction| !satisfaction.reason.trim().is_empty())
        .filter_map(|satisfaction| satisfaction.requirement.as_deref())
        .map(normalize_requirement_name)
        .collect::<HashSet<_>>();

    requirements
        .iter()
        .filter(|requirement| {
            !satisfied_requirements.contains(&normalize_requirement_name(&requirement.name))
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

    #[test]
    fn safety_doc_headings_match_supported_styles() {
        assert!(line_has_safety_heading("# Safety"));
        assert!(line_has_safety_heading("    ## SAFETY   "));
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
                },
                SafetyRequirement {
                    name: String::from("initialized"),
                    condition: String::from("pointer must reference initialized memory"),
                },
                SafetyRequirement {
                    name: String::from("aligned"),
                    condition: String::new(),
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
            },
            SafetyRequirement {
                name: String::from("initialized"),
                condition: String::from("pointer must be initialized"),
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
            }]
        );
    }
}
