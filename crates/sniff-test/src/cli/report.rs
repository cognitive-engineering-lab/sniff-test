//! Workspace-only JSON analysis report types.

use rustc_middle::ty::TyCtxt;
use serde::Serialize;

use super::findings::ResolvedFinding;

pub(crate) const REPORT_FORMAT_VERSION: u32 = 11;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct AnalysisArtifactReport {
    pub(crate) reason: String,
    pub(crate) format_version: u32,
    pub(crate) tool_version: String,
    pub(crate) rustc_version: String,
    pub(crate) artifact: ReportArtifact,
    pub(crate) dependencies: Vec<ReportDependency>,
    pub(crate) findings: Vec<ResolvedFinding>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ReportArtifact {
    pub(crate) artifact_id: String,
    pub(crate) crate_name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ReportDependency {
    pub(crate) extern_name: String,
    pub(crate) artifact_id: String,
}

/// Internal rustc-unit classification. This is deliberately not serialized:
/// every public report is a workspace report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrateOutputScope {
    Workspace,
    Dependency,
}

pub(crate) fn render_span(tcx: TyCtxt<'_>, span: rustc_span::Span) -> String {
    tcx.sess.source_map().span_to_diagnostic_string(span)
}

#[cfg(test)]
mod tests {
    use super::{AnalysisArtifactReport, REPORT_FORMAT_VERSION, ReportArtifact, ReportDependency};

    #[test]
    fn workspace_report_v11_has_no_scope_field() {
        let report = AnalysisArtifactReport {
            reason: String::from("sniff-test-artifact"),
            format_version: REPORT_FORMAT_VERSION,
            tool_version: String::from("0.1.0"),
            rustc_version: String::from("rustc test"),
            artifact: ReportArtifact {
                artifact_id: String::from("workspace-123"),
                crate_name: String::from("workspace"),
            },
            dependencies: vec![ReportDependency {
                extern_name: String::from("renamed"),
                artifact_id: String::from("dependency-456"),
            }],
            findings: Vec::new(),
        };

        let value = serde_json::to_value(report).expect("report should serialize");
        let object = value.as_object().expect("report object");
        assert_eq!(object["format-version"], REPORT_FORMAT_VERSION);
        assert!(!object.contains_key("scope"));
    }
}
