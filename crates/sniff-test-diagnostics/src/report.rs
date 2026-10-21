//! Workspace-only JSON analysis report types.

use rustc_middle::ty::TyCtxt;
pub use sniff_test_report::{REPORT_FORMAT_VERSION, ReportArtifact};
pub type AnalysisArtifactReport =
    sniff_test_report::AnalysisArtifactReport<super::findings::ResolvedFinding>;

#[must_use]
pub fn render_span(tcx: TyCtxt<'_>, span: rustc_span::Span) -> String {
    tcx.sess.source_map().span_to_diagnostic_string(span)
}

#[cfg(test)]
mod tests {
    use super::{AnalysisArtifactReport, REPORT_FORMAT_VERSION, ReportArtifact};

    #[test]
    fn workspace_report_serializes_its_public_fields() {
        assert_eq!(REPORT_FORMAT_VERSION, 24);

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
                "format-version": 24,
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
