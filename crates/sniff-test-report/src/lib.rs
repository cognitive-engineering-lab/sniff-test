//! Compiler-independent report envelope and structured semantic facts.
pub mod source_overrides;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const REPORT_FORMAT_VERSION: u32 = 25;

pub fn content_hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AnalysisArtifactReport<F = serde_json::Value> {
    pub reason: String,
    pub format_version: u32,
    pub tool_version: String,
    pub rustc_version: String,
    pub artifact: ReportArtifact,
    pub findings: Vec<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ReportArtifact {
    pub crate_name: String,
}

/// Byte ranges refer to the original UTF-8 file, including CRLF and a possible BOM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub path: String,
    pub source_id: String,
    pub hash: String,
    pub start: usize,
    pub end: usize,
    pub available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceStep {
    pub caller: String,
    pub target: Option<String>,
    pub kind: TraceKind,
    pub marker_association: MarkerAssociation,
    pub location: Option<Location>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TraceKind {
    DirectCall,
    TailCall,
    MacroExpansion,
    ConstBody,
    ModeledCall,
    Assert,
    IndirectCall,
    EffectOperation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MarkerAssociation {
    SourceInvocation,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticFacts {
    /// Optional presentation metadata; absent in older reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_source: Option<DirectSourceKey>,
    pub effect: String,
    pub obligation: Option<String>,
    pub justification: Option<String>,
    pub source: Option<Location>,
    pub root: Option<Location>,
    pub enclosing_function: Option<Location>,
    pub justification_site: Option<Location>,
    pub contract: Option<Location>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obligation_documentation: Option<ObligationDocumentation>,
    pub trace: Vec<TraceStep>,
    #[serde(default)]
    pub override_targets: Vec<OverrideTarget>,
}

/// Effective contract section presented while auditing a documented effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationDocumentation {
    pub function: String,
    pub markdown: String,
}

/// Translate rustc-normalized positions to original file offsets.
pub fn original_offset(source: &str, normalized: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut raw = if source.starts_with('\u{feff}') { 3 } else { 0 };
    let mut pos = 0;
    while pos < normalized && raw < bytes.len() {
        if bytes[raw] == b'\r' && bytes.get(raw + 1) == Some(&b'\n') {
            raw += 1;
        }
        raw += 1;
        pos += 1;
    }
    (pos == normalized && source.is_char_boundary(raw)).then_some(raw)
}

#[cfg(test)]
mod tests {
    #[test]
    fn older_semantic_facts_without_direct_source_remain_readable() {
        let value = serde_json::json!({
            "effect": "custom", "obligation": null, "justification": null,
            "source": null, "root": null, "enclosing_function": null,
            "justification_site": null, "contract": null, "trace": []
        });
        let facts: super::SemanticFacts = serde_json::from_value(value).unwrap();
        assert!(facts.direct_source.is_none());
        assert!(facts.obligation_documentation.is_none());
        assert!(
            serde_json::to_value(facts)
                .unwrap()
                .get("direct_source")
                .is_none()
        );
    }

    #[test]
    fn offsets_preserve_crlf_bom_and_unicode() {
        assert_eq!(super::original_offset("\u{feff}a\r\nλ", 2), Some(6));
        assert_eq!(super::original_offset("λ", 1), None);
        assert_eq!(super::original_offset("λ", 2), Some(2));
    }
}

/// Exact compiler-fact identity. Offsets here are normalized rustc bytes;
/// the separate display location uses original on-disk UTF-8 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct OverrideSelector {
    pub definition: String,
    pub namespace: String,
    pub source_id: String,
    pub source_hash: String,
    pub crate_name: String,
    pub version: String,
    pub line: u32,
    /// Effective rustdoc before editing, including configured replacements.
    pub documentation: String,
    pub justification_headers: Vec<String>,
    pub source_path: String,
    pub start: u64,
    pub end: u64,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
}
impl OverrideSelector {
    /// Compare the portable target, excluding compiler identities tied to a checkout.
    pub fn same_target(&self, other: &Self) -> bool {
        self.namespace == other.namespace
            && self.crate_name == other.crate_name
            && self.version == other.version
            && self.source_path == other.source_path
            && self.source_hash == other.source_hash
            && self.start == other.start
            && self.end == other.end
            && self.kind == other.kind
            && self.site == other.site
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideTarget {
    pub action: String,
    pub location: Location,
    pub selector: OverrideSelector,
}

/// Complete direct justification identity, ordered exactly as CLI source ties.
/// Class and owner numbers preserve the analyzer enum ordering, not spelling order.
/// Caller paths and report roots deliberately do not participate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DirectSourceKey {
    pub source: (String, String, u64, u64),
    pub kind: (String, u8, Option<String>),
    pub function: Option<String>,
    pub target: Option<String>,
    pub owner: Option<(u8, Option<String>)>,
    pub missing_requirements: Vec<String>,
    pub requirements: Vec<String>,
}

/// Presentation rank shared by CLI diagnostics and the audit source groups.
pub fn justification_impact_rank<T: Ord>(
    reports: usize,
    roots: usize,
    source: T,
) -> (std::cmp::Reverse<usize>, std::cmp::Reverse<usize>, T) {
    (std::cmp::Reverse(reports), std::cmp::Reverse(roots), source)
}
