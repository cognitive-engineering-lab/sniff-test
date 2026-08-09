//! Workspace-only JSON analysis report types.

use rustc_middle::ty::TyCtxt;
use serde::Serialize;

use super::findings::ResolvedFinding;

pub(crate) const REPORT_FORMAT_VERSION: u32 = 13;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct AnalysisArtifactReport {
    pub(crate) reason: String,
    pub(crate) format_version: u32,
    pub(crate) tool_version: String,
    pub(crate) rustc_version: String,
    pub(crate) artifact: ReportArtifact,
    pub(crate) findings: Vec<ResolvedFinding>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ReportArtifact {
    pub(crate) crate_name: String,
}

pub(crate) fn render_span(tcx: TyCtxt<'_>, span: rustc_span::Span) -> String {
    tcx.sess.source_map().span_to_diagnostic_string(span)
}

#[cfg(test)]
mod tests {
    use super::{AnalysisArtifactReport, REPORT_FORMAT_VERSION, ReportArtifact};

    #[test]
    fn workspace_report_v13_serializes_its_public_fields() {
        assert_eq!(REPORT_FORMAT_VERSION, 13);

        let report = AnalysisArtifactReport {
            reason: String::from("sniff-test-artifact"),
            format_version: REPORT_FORMAT_VERSION,
            tool_version: String::from("0.1.0"),
            rustc_version: String::from("rustc test"),
            artifact: ReportArtifact {
                crate_name: String::from("workspace"),
            },
            findings: Vec::new(),
        };

        assert_eq!(
            serde_json::to_value(report).expect("report should serialize"),
            serde_json::json!({
                "reason": "sniff-test-artifact",
                "format-version": 13,
                "tool-version": "0.1.0",
                "rustc-version": "rustc test",
                "artifact": {
                    "crate-name": "workspace",
                },
                "findings": [],
            })
        );
    }
}
