use crate::config::ContractDocOverrides;
use crate::namespace::canonical_namespace;
use crate::safety::{
    SafetyAnalysis, SafetyFinding, render_safety_requirement, safety_call_label,
    safety_callee_name, safety_op_label,
};
use rustc_middle::ty::TyCtxt;

use super::diagnostics::safety_finding_diagnostic;
use super::report::{Finding, render_span};

pub(super) fn safety_finding_reports(
    tcx: TyCtxt<'_>,
    analysis: SafetyAnalysis,
    overrides: &ContractDocOverrides,
) -> Vec<Finding> {
    analysis
        .findings
        .into_iter()
        .map(|finding| safety_finding_report(tcx, finding, overrides))
        .collect()
}

fn safety_finding_report(
    tcx: TyCtxt<'_>,
    finding: SafetyFinding,
    overrides: &ContractDocOverrides,
) -> Finding {
    let kind = finding.kind();
    let diagnostic = safety_finding_diagnostic(tcx, &finding, overrides);
    match finding {
        SafetyFinding::MissingSafetyDocs { def_id, span } => {
            let function = canonical_namespace(tcx, def_id);
            Finding {
                kind: kind.into(),
                root: None,
                root_kind: None,
                function: Some(function.clone()),
                target: None,
                span: Some(render_span(tcx, span)),
                reason: format!("public unsafe function `{function}` is missing # Safety docs"),
                trace: Vec::new(),
                missing_requirements: Vec::new(),
                requirements: Vec::new(),
                diagnostic,
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
            Finding {
                kind: kind.into(),
                root: None,
                root_kind: None,
                function: Some(canonical_namespace(tcx, caller)),
                target: Some(target.clone()),
                span: Some(render_span(tcx, span)),
                reason: format!("{call} to `{target}` has no `// SAFETY:` justification"),
                trace: Vec::new(),
                missing_requirements: Vec::new(),
                requirements: Vec::new(),
                diagnostic,
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
            Finding {
                kind: kind.into(),
                root: None,
                root_kind: None,
                function: Some(canonical_namespace(tcx, caller)),
                target: Some(target.clone()),
                span: Some(render_span(tcx, span)),
                reason: format!("{call} to `{target}` does not satisfy all # Safety requirements"),
                trace: Vec::new(),
                missing_requirements,
                requirements: Vec::new(),
                diagnostic,
            }
        }
        SafetyFinding::OpMissingJustification { caller, op, span } => {
            let operation = safety_op_label(op);
            Finding {
                kind: kind.into(),
                root: None,
                root_kind: None,
                function: Some(canonical_namespace(tcx, caller)),
                target: None,
                span: Some(render_span(tcx, span)),
                reason: format!("unsafe operation ({operation}) has no `// SAFETY:` justification"),
                trace: Vec::new(),
                missing_requirements: Vec::new(),
                requirements: Vec::new(),
                diagnostic,
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
            Finding {
                kind: kind.into(),
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
                diagnostic,
            }
        }
    }
}
