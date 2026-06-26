//! Safety documentation and call-site justification analysis.
//!
//! This pass checks that public unsafe functions document a `# Safety`
//! contract and that safety-obligation call sites have nearby `// SAFETY:`
//! justifications satisfying any named requirements listed by the callee.

use std::collections::HashSet;

use rustc_hir::def::DefKind;
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_hir::{BlockCheckMode, Expr, ExprKind, UnsafeSource, intravisit};
use rustc_middle::ty::{self, TyCtxt, TypeckResults};
use rustc_span::Span;

use crate::config::{LintLevel, SafetyConfig, SafetyLintConfig};
use crate::contracts::{
    ContractDocSummary, ContractKind, ContractRequirement, contract_doc_summary,
    normalize_requirement_name,
};
use crate::namespace::canonical_namespace;
use crate::source_markers::{SafetySatisfaction, span_safety_satisfactions};

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyFindingKind {
    MissingSafetyDocs,
    UnsafeCallMissingJustification,
    UnsafeCallMissingRequirements,
    SafetyObligationMissingJustification,
    SafetyObligationMissingRequirements,
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
        if matches!(
            tcx.def_kind(owner),
            DefKind::Fn | DefKind::AssocFn | DefKind::Closure
        ) {
            collect_safety_call_findings(tcx, owner, config, &mut analysis);
        }
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

fn collect_safety_call_findings(
    tcx: TyCtxt<'_>,
    owner: LocalDefId,
    config: &SafetyConfig,
    analysis: &mut SafetyAnalysis,
) {
    if config.ignores_def(tcx, owner.to_def_id()) {
        return;
    }

    let Some(body) = tcx.hir_maybe_body_owned_by(owner) else {
        return;
    };
    let typeck = tcx.typeck(owner);
    let mut visitor = SafetyCallVisitor {
        tcx,
        owner,
        config,
        typeck,
        safety_scopes: Vec::new(),
        findings: Vec::new(),
    };

    intravisit::Visitor::visit_body(&mut visitor, body);
    analysis.findings.extend(visitor.findings);
}

struct SafetyCallVisitor<'config, 'tcx> {
    tcx: TyCtxt<'tcx>,
    owner: LocalDefId,
    config: &'config SafetyConfig,
    typeck: &'tcx TypeckResults<'tcx>,
    safety_scopes: Vec<Vec<SafetySatisfaction>>,
    findings: Vec<SafetyFinding>,
}

impl<'tcx> SafetyCallVisitor<'_, 'tcx> {
    fn visit_user_unsafe_block(
        &mut self,
        expr: &'tcx Expr<'tcx>,
        block: &'tcx rustc_hir::Block<'tcx>,
    ) {
        let satisfactions = span_safety_satisfactions(self.tcx, expr.span);
        self.safety_scopes.push(satisfactions);
        intravisit::walk_block(self, block);
        self.safety_scopes
            .pop()
            .expect("unsafe block scope should be present");
    }

    fn inspect_safety_call(&mut self, expr: &'tcx Expr<'tcx>) {
        let Some(call) = self.safety_call(expr) else {
            return;
        };
        if self.ignores_callee(call.callee) {
            return;
        }
        let satisfactions = self.applicable_satisfactions(expr.span);

        if let SafetyCallee::Def(def_id) = call.callee {
            let requirements = safety_requirements(self.tcx, def_id);
            if !requirements.is_empty() {
                let missing = missing_safety_requirements(&requirements, &satisfactions);
                if !missing.is_empty() {
                    self.findings.push(SafetyFinding::CallMissingRequirements {
                        caller: self.owner.to_def_id(),
                        callee: call.callee,
                        call_kind: call.kind,
                        span: expr.span,
                        missing_requirements: missing,
                    });
                }
                return;
            }
        }

        if satisfactions.is_empty() {
            self.findings.push(SafetyFinding::CallMissingJustification {
                caller: self.owner.to_def_id(),
                callee: call.callee,
                call_kind: call.kind,
                span: expr.span,
            });
        }
    }

    fn ignores_callee(&self, callee: SafetyCallee) -> bool {
        matches!(callee, SafetyCallee::Def(def_id) if self.config.ignores_def(self.tcx, def_id))
    }

    fn safety_call(&self, expr: &'tcx Expr<'tcx>) -> Option<SafetyCall> {
        match expr.kind {
            ExprKind::Call(callee, _) => self.safety_call_from_call_target(callee),
            ExprKind::MethodCall(..) => self
                .typeck
                .type_dependent_def_id(expr.hir_id)
                .and_then(|def_id| self.safety_call_from_def(def_id)),
            _ => None,
        }
    }

    fn safety_call_from_call_target(&self, callee: &'tcx Expr<'tcx>) -> Option<SafetyCall> {
        match self.typeck.expr_ty_adjusted(callee).kind() {
            ty::FnDef(def_id, _) => self.safety_call_from_def(*def_id),
            ty::FnPtr(_, header) if header.safety().is_unsafe() => Some(SafetyCall {
                callee: SafetyCallee::FunctionPointer,
                kind: SafetyCallKind::Unsafe,
            }),
            _ => None,
        }
    }

    fn safety_call_from_def(&self, def_id: DefId) -> Option<SafetyCall> {
        if fn_def_is_unsafe(self.tcx, def_id) {
            Some(SafetyCall {
                callee: SafetyCallee::Def(def_id),
                kind: SafetyCallKind::Unsafe,
            })
        } else if self.config.marks_safety_obligation_def(self.tcx, def_id) {
            Some(SafetyCall {
                callee: SafetyCallee::Def(def_id),
                kind: SafetyCallKind::ConfiguredObligation,
            })
        } else {
            None
        }
    }

    fn applicable_satisfactions(&self, span: Span) -> Vec<SafetySatisfaction> {
        self.safety_scopes
            .iter()
            .flat_map(|scope| scope.iter().cloned())
            .chain(span_safety_satisfactions(self.tcx, span))
            .collect()
    }
}

impl<'tcx> intravisit::Visitor<'tcx> for SafetyCallVisitor<'_, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) -> Self::Result {
        match expr.kind {
            ExprKind::Closure(_) => {}
            ExprKind::Block(block, _)
                if matches!(
                    block.rules,
                    BlockCheckMode::UnsafeBlock(UnsafeSource::UserProvided)
                ) =>
            {
                self.visit_user_unsafe_block(expr, block);
            }
            _ => {
                self.inspect_safety_call(expr);
                intravisit::walk_expr(self, expr);
            }
        }
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
