use crate::config::{LintLevel, SafetyLintConfig};
use crate::namespace::canonical_namespace;
use crate::safety::{
    SafetyAnalysis, SafetyFinding, render_safety_requirement, safety_call_label,
    safety_callee_name, safety_op_label,
};
use rustc_middle::ty::TyCtxt;

use super::report::{FindingReport, render_span};

pub(super) fn safety_finding_reports(
    tcx: TyCtxt<'_>,
    analysis: SafetyAnalysis,
    lints: SafetyLintConfig,
    ambiguous_obligations: LintLevel,
) -> Vec<FindingReport> {
    analysis
        .findings
        .into_iter()
        .filter_map(|finding| {
            let level = finding.kind().lint_level(lints, ambiguous_obligations);
            (level != LintLevel::Allow).then(|| safety_finding_report(tcx, finding, level))
        })
        .collect()
}

fn safety_finding_report(
    tcx: TyCtxt<'_>,
    finding: SafetyFinding,
    level: LintLevel,
) -> FindingReport {
    let kind = finding.kind();
    match finding {
        SafetyFinding::MissingSafetyDocs { def_id, span } => {
            let function = canonical_namespace(tcx, def_id);
            FindingReport {
                kind: kind.into(),
                level,
                root: None,
                root_kind: None,
                function: Some(function.clone()),
                target: None,
                span: Some(render_span(tcx, span)),
                reason: format!("public unsafe function `{function}` is missing # Safety docs"),
                trace: Vec::new(),
                missing_requirements: Vec::new(),
                requirements: Vec::new(),
            }
        }
        SafetyFinding::CallMissingJustification {
            caller,
            callee,
            call_kind,
            span,
        } => {
            let target = safety_callee_name(tcx, callee);
            let call = safety_call_label(call_kind);
            FindingReport {
                kind: kind.into(),
                level,
                root: None,
                root_kind: None,
                function: Some(canonical_namespace(tcx, caller)),
                target: Some(target.clone()),
                span: Some(render_span(tcx, span)),
                reason: format!("{call} to `{target}` has no `// SAFETY:` justification"),
                trace: Vec::new(),
                missing_requirements: Vec::new(),
                requirements: Vec::new(),
            }
        }
        SafetyFinding::CallMissingRequirements {
            caller,
            callee,
            call_kind,
            span,
            missing_requirements,
        } => {
            let target = safety_callee_name(tcx, callee);
            let call = safety_call_label(call_kind);
            let missing_requirements = missing_requirements
                .iter()
                .map(render_safety_requirement)
                .collect();
            FindingReport {
                kind: kind.into(),
                level,
                root: None,
                root_kind: None,
                function: Some(canonical_namespace(tcx, caller)),
                target: Some(target.clone()),
                span: Some(render_span(tcx, span)),
                reason: format!("{call} to `{target}` does not satisfy all # Safety requirements"),
                trace: Vec::new(),
                missing_requirements,
                requirements: Vec::new(),
            }
        }
        SafetyFinding::OpMissingJustification { caller, op, span } => {
            let operation = safety_op_label(op);
            FindingReport {
                kind: kind.into(),
                level,
                root: None,
                root_kind: None,
                function: Some(canonical_namespace(tcx, caller)),
                target: None,
                span: Some(render_span(tcx, span)),
                reason: format!("unsafe operation ({operation}) has no `// SAFETY:` justification"),
                trace: Vec::new(),
                missing_requirements: Vec::new(),
                requirements: Vec::new(),
            }
        }
        SafetyFinding::AmbiguousObligationName {
            def_id,
            normalized_name,
            requirements,
        } => {
            let function = canonical_namespace(tcx, def_id);
            let span = requirements
                .first()
                .map_or_else(|| tcx.def_span(def_id), |requirement| requirement.span);
            let requirements = requirements.iter().map(render_safety_requirement).collect();
            FindingReport {
                kind: kind.into(),
                level,
                root: None,
                root_kind: None,
                function: Some(function.clone()),
                target: None,
                span: Some(render_span(tcx, span)),
                reason: format!(
                    "`{function}` has multiple # Safety requirements named `{normalized_name}`"
                ),
                trace: Vec::new(),
                missing_requirements: Vec::new(),
                requirements,
            }
        }
    }
}
