//! Compiler-independent report envelope and structured semantic facts.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const REPORT_FORMAT_VERSION: u32 = 23;

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
    pub effect: String,
    pub obligation: Option<String>,
    pub justification: Option<String>,
    pub source: Option<Location>,
    pub root: Option<Location>,
    pub contract: Option<Location>,
    pub trace: Vec<TraceStep>,
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
    fn offsets_preserve_crlf_bom_and_unicode() {
        assert_eq!(super::original_offset("\u{feff}a\r\nλ", 2), Some(6));
        assert_eq!(super::original_offset("λ", 1), None);
        assert_eq!(super::original_offset("λ", 2), Some(2));
    }
}
