//! Verified integration of cached source locations with rustc's active source map.
//!
//! Cached filenames are only hints for locating source. A span is returned
//! after the loaded file's stable identity, content hash, normalized byte
//! length, and requested byte range all match the artifact IR.

use std::collections::BTreeMap;
use std::fmt;
use std::hash::Hasher;
use std::io;
use std::path::Path;
use std::sync::Arc;

use rustc_data_structures::{fingerprint::Fingerprint, stable_hasher::StableHasher};
use rustc_middle::ty::TyCtxt;
use rustc_span::source_map::SourceMap;
use rustc_span::{BytePos, Pos, SourceFile, Span};

use super::facts::encoded::ArtifactFactIr;
use super::facts::human::markers::{MarkerOccurrenceEntity, MarkerOccurrenceHasSourceAnchor};
use super::facts::program::{SourceAnchorEntity, SourceAnchorInFile, SourceFileEntity};
use super::facts::registry::SchemaRegistry;
use super::facts::schema::RowSchema;
use super::facts::view::{ArtifactDbView, IndexedRow};
use super::ir::{SourceFileId, SourceFileIr, SourceRangeIr};

/// Verifies every source chain that permanently owns a human marker.
///
/// This validates the typed relation cardinality before consulting any
/// filename. Missing producer tables, missing or duplicate links, and
/// inconsistent stable keys all reject the cache rather than silently turning
/// marker evidence into an empty set.
pub(crate) fn verify_cached_permanent_marker_sources_in(
    source_map: &SourceMap,
    facts: &ArtifactFactIr,
    schemas: &SchemaRegistry,
) -> Result<(), CachedSourceError> {
    require_permanent_source_tables(facts, schemas)?;
    let view = ArtifactDbView::open(facts, schemas)
        .map_err(|error| malformed_permanent_source_chain(error.to_string()))?;
    let occurrences = view
        .indexed_rows::<MarkerOccurrenceEntity>()
        .map_err(|error| malformed_permanent_source_chain(error.to_string()))?;
    let anchors = view
        .indexed_rows::<SourceAnchorEntity>()
        .map_err(|error| malformed_permanent_source_chain(error.to_string()))?;
    let files = view
        .indexed_rows::<SourceFileEntity>()
        .map_err(|error| malformed_permanent_source_chain(error.to_string()))?;
    let active_files = active_source_files(source_map);
    let anchor_by_occurrence = marker_anchor_rows(view, occurrences.len())?;
    let file_by_anchor = anchor_file_rows(view, anchors.len())?;
    verify_permanent_marker_ranges(
        source_map,
        &occurrences,
        &anchors,
        &files,
        &anchor_by_occurrence,
        &file_by_anchor,
        &active_files,
    )
}

fn marker_anchor_rows(
    view: ArtifactDbView<'_>,
    occurrence_count: usize,
) -> Result<Vec<Option<u32>>, CachedSourceError> {
    let mut anchor_by_occurrence = vec![None; occurrence_count];
    for relation in view
        .relations::<MarkerOccurrenceHasSourceAnchor>()
        .map_err(|error| malformed_permanent_source_chain(error.to_string()))?
    {
        let occurrence = usize::try_from(relation.from.row()).map_err(|_| {
            malformed_permanent_source_chain("marker occurrence row does not fit usize")
        })?;
        let anchor = relation.to.row();
        let slot = anchor_by_occurrence.get_mut(occurrence).ok_or_else(|| {
            malformed_permanent_source_chain(format!(
                "marker occurrence row {} is outside its entity table",
                relation.from.row()
            ))
        })?;
        if slot.replace(anchor).is_some() {
            return Err(malformed_permanent_source_chain(format!(
                "marker occurrence row {} has multiple physical source anchors",
                relation.from.row()
            )));
        }
    }
    Ok(anchor_by_occurrence)
}

fn anchor_file_rows(
    view: ArtifactDbView<'_>,
    anchor_count: usize,
) -> Result<Vec<Option<u32>>, CachedSourceError> {
    let mut file_by_anchor = vec![None; anchor_count];
    for relation in view
        .relations::<SourceAnchorInFile>()
        .map_err(|error| malformed_permanent_source_chain(error.to_string()))?
    {
        let anchor = usize::try_from(relation.from.row()).map_err(|_| {
            malformed_permanent_source_chain("source anchor row does not fit usize")
        })?;
        let file = relation.to.row();
        let slot = file_by_anchor.get_mut(anchor).ok_or_else(|| {
            malformed_permanent_source_chain(format!(
                "source anchor row {} is outside its entity table",
                relation.from.row()
            ))
        })?;
        if slot.replace(file).is_some() {
            return Err(malformed_permanent_source_chain(format!(
                "source anchor row {} has multiple source files",
                relation.from.row()
            )));
        }
    }
    Ok(file_by_anchor)
}

fn verify_permanent_marker_ranges(
    source_map: &SourceMap,
    occurrences: &[IndexedRow<MarkerOccurrenceEntity>],
    anchors: &[IndexedRow<SourceAnchorEntity>],
    files: &[IndexedRow<SourceFileEntity>],
    anchor_by_occurrence: &[Option<u32>],
    file_by_anchor: &[Option<u32>],
    active_files: &BTreeMap<SourceFileId, Arc<SourceFile>>,
) -> Result<(), CachedSourceError> {
    let mut loaded_files = vec![None::<Option<Arc<SourceFile>>>; files.len()];
    for (occurrence_index, occurrence) in occurrences.iter().enumerate() {
        let anchor_row = anchor_by_occurrence[occurrence_index].ok_or_else(|| {
            malformed_permanent_source_chain(format!(
                "marker occurrence row {} has no physical source anchor",
                occurrence.reference.row
            ))
        })?;
        let anchor_index = usize::try_from(anchor_row).map_err(|_| {
            malformed_permanent_source_chain("source anchor row does not fit usize")
        })?;
        let anchor = anchors.get(anchor_index).ok_or_else(|| {
            malformed_permanent_source_chain(format!(
                "source anchor row {anchor_row} is outside its entity table"
            ))
        })?;
        if occurrence.data.key().anchor() != anchor.data.anchor() {
            return Err(malformed_permanent_source_chain(format!(
                "marker occurrence row {} does not identify physical source anchor row {anchor_row}",
                occurrence.reference.row
            )));
        }

        let file_row = file_by_anchor[anchor_index].ok_or_else(|| {
            malformed_permanent_source_chain(format!(
                "source anchor row {anchor_row} has no source file"
            ))
        })?;
        let file_index = usize::try_from(file_row)
            .map_err(|_| malformed_permanent_source_chain("source file row does not fit usize"))?;
        let file = files.get(file_index).ok_or_else(|| {
            malformed_permanent_source_chain(format!(
                "source file row {file_row} is outside its entity table"
            ))
        })?;
        if anchor.data.anchor().file() != file.data.id() {
            return Err(malformed_permanent_source_chain(format!(
                "source anchor row {anchor_row} identifies file `{}`, but relation names `{}`",
                anchor.data.anchor().file(),
                file.data.id()
            )));
        }

        let source = SourceFileIr {
            id: SourceFileId::new(file.data.id()),
            filename: file.data.filename().to_owned(),
            content_hash: file.data.content_hash().to_owned(),
            byte_len: file.data.byte_len(),
        };
        let range = SourceRangeIr {
            file: source.id.clone(),
            byte_start: anchor.data.anchor().byte_start(),
            byte_end: anchor.data.anchor().byte_end(),
        };
        validate_declared_range(&source, &range)?;
        let verified = &mut loaded_files[file_index];
        if verified.is_none() {
            *verified = Some(
                match load_verified_cached_source_from_index(source_map, &source, active_files) {
                    Ok(file) => Some(file),
                    Err(error) if error.is_absent_from_disk() => None,
                    Err(error) => return Err(error),
                },
            );
        }
        let verified = verified.as_ref().ok_or_else(|| {
            malformed_permanent_source_chain("source verification state was not initialized")
        })?;
        if let Some(file) = verified {
            cached_source_range_span(source_map, &source, &range, file)?;
        }
    }
    Ok(())
}

fn require_permanent_source_tables(
    facts: &ArtifactFactIr,
    schemas: &SchemaRegistry,
) -> Result<(), CachedSourceError> {
    for schema in [
        MarkerOccurrenceEntity::ID,
        MarkerOccurrenceHasSourceAnchor::ID,
        SourceAnchorEntity::ID,
        SourceAnchorInFile::ID,
        SourceFileEntity::ID,
    ] {
        let schema = schema.parse().map_err(|error| {
            malformed_permanent_source_chain(format!(
                "built-in source schema ID is invalid: {error}"
            ))
        })?;
        if schemas.descriptor(&schema).is_none()
            || !facts.tables.iter().any(|table| table.schema == schema)
        {
            return Err(CachedSourceError::MissingPermanentSourceSchema {
                schema: schema.to_string(),
            });
        }
    }
    Ok(())
}

fn malformed_permanent_source_chain(reason: impl Into<String>) -> CachedSourceError {
    CachedSourceError::MalformedPermanentSourceFacts {
        reason: reason.into(),
    }
}

/// Loads and verifies one cached source range in rustc's active source map.
///
/// Callers should treat every error as a nonfatal signal to render an
/// unspanned diagnostic. No span from unverified source is ever returned.
pub(crate) fn cached_source_span(
    tcx: TyCtxt<'_>,
    source: &SourceFileIr,
    range: &SourceRangeIr,
) -> Result<Span, CachedSourceError> {
    cached_source_span_in(tcx.sess.source_map(), source, range)
}

pub(crate) fn cached_source_span_in(
    source_map: &SourceMap,
    source: &SourceFileIr,
    range: &SourceRangeIr,
) -> Result<Span, CachedSourceError> {
    validate_declared_range(source, range)?;
    let file = load_verified_cached_source(source_map, source)?;
    cached_source_range_span(source_map, source, range, &file)
}

fn load_verified_cached_source(
    source_map: &SourceMap,
    source: &SourceFileIr,
) -> Result<Arc<SourceFile>, CachedSourceError> {
    load_verified_cached_source_from_index(source_map, source, &active_source_files(source_map))
}

fn active_source_files(source_map: &SourceMap) -> BTreeMap<SourceFileId, Arc<SourceFile>> {
    source_map
        .files()
        .iter()
        .map(|file| (stable_source_file_id(file), Arc::clone(file)))
        .collect()
}

fn load_verified_cached_source_from_index(
    source_map: &SourceMap,
    source: &SourceFileIr,
    active_files: &BTreeMap<SourceFileId, Arc<SourceFile>>,
) -> Result<Arc<SourceFile>, CachedSourceError> {
    // Prefer an existing SourceFile to avoid loading a duplicate. The analysis
    // identity is independent of rustc's exporting-crate identity, so loading
    // a verified dependency or sysroot file below is also valid.
    let existing = active_files.get(&source.id).cloned();
    let file = match existing {
        Some(file) => file,
        None => source_map
            .load_file(Path::new(&source.filename))
            .map_err(|error| CachedSourceError::SourceUnavailable {
                filename: source.filename.clone(),
                kind: error.kind(),
                message: error.to_string(),
            })?,
    };
    verify_loaded_file(source, &file)?;
    if !source_map.ensure_source_file_source_present(&file) {
        return Err(CachedSourceError::SourceUnavailable {
            filename: source.filename.clone(),
            kind: io::ErrorKind::NotFound,
            message: String::from("rustc could not load source matching the recorded content hash"),
        });
    }
    Ok(file)
}

fn cached_source_range_span(
    source_map: &SourceMap,
    source: &SourceFileIr,
    range: &SourceRangeIr,
    file: &SourceFile,
) -> Result<Span, CachedSourceError> {
    let start =
        u32::try_from(range.byte_start).map_err(|_| CachedSourceError::RangeOutOfBounds {
            byte_start: range.byte_start,
            byte_end: range.byte_end,
            byte_len: source.byte_len,
        })?;
    let end = u32::try_from(range.byte_end).map_err(|_| CachedSourceError::RangeOutOfBounds {
        byte_start: range.byte_start,
        byte_end: range.byte_end,
        byte_len: source.byte_len,
    })?;
    let lo =
        file.start_pos
            .0
            .checked_add(start)
            .ok_or(CachedSourceError::GlobalPositionOverflow {
                filename: source.filename.clone(),
            })?;
    let hi =
        file.start_pos
            .0
            .checked_add(end)
            .ok_or(CachedSourceError::GlobalPositionOverflow {
                filename: source.filename.clone(),
            })?;
    let span = Span::with_root_ctxt(BytePos(lo), BytePos(hi));
    source_map
        .span_to_snippet(span)
        .map_err(|_| CachedSourceError::InvalidSourceRange {
            byte_start: range.byte_start,
            byte_end: range.byte_end,
        })?;
    Ok(span)
}

fn validate_declared_range(
    source: &SourceFileIr,
    range: &SourceRangeIr,
) -> Result<(), CachedSourceError> {
    if range.file != source.id {
        return Err(CachedSourceError::RangeSourceMismatch {
            source: source.id.as_str().to_owned(),
            range: range.file.as_str().to_owned(),
        });
    }
    if range.byte_start > range.byte_end || range.byte_end > source.byte_len {
        return Err(CachedSourceError::RangeOutOfBounds {
            byte_start: range.byte_start,
            byte_end: range.byte_end,
            byte_len: source.byte_len,
        });
    }
    Ok(())
}

fn verify_loaded_file(
    expected: &SourceFileIr,
    actual: &SourceFile,
) -> Result<(), CachedSourceError> {
    let actual_hash = actual.src_hash.to_string();
    if actual_hash != expected.content_hash {
        return Err(CachedSourceError::ContentHashMismatch {
            filename: expected.filename.clone(),
            expected: expected.content_hash.clone(),
            actual: actual_hash,
        });
    }
    let actual_len = u64::from(actual.normalized_source_len.to_u32());
    if actual_len != expected.byte_len {
        return Err(CachedSourceError::NormalizedLengthMismatch {
            filename: expected.filename.clone(),
            expected: expected.byte_len,
            actual: actual_len,
        });
    }
    let actual_id = stable_source_file_id(actual);
    if actual_id != expected.id {
        return Err(CachedSourceError::StableIdentityMismatch {
            expected: expected.id.as_str().to_owned(),
            actual: actual_id.as_str().to_owned(),
        });
    }
    Ok(())
}

/// Returns the persisted source locator used by artifact IR.
///
/// rustc commonly keeps crate-local filenames such as `src/lib.rs`. Those
/// names become ambiguous as soon as IR from multiple crates is composed, so
/// resolve a real relative path while extraction is still running in the
/// defining crate's working directory. Virtual and unavailable names remain
/// untouched and will safely degrade to unspanned diagnostics later.
pub(crate) fn source_filename(file: &SourceFile) -> String {
    let filename = file.name.prefer_local_unconditionally().to_string();
    let path = Path::new(&filename);
    if path.is_relative()
        && path.exists()
        && let Ok(absolute) = std::path::absolute(path)
    {
        return absolute.to_string_lossy().into_owned();
    }
    filename
}

/// Computes the serialized identity used by source files in artifact IR.
///
/// `SourceFile::stable_id` includes the exporting crate context. Loading the
/// same verified file dynamically in a workspace session gives it a different
/// rustc identity, making valid dependency spans impossible to reconstruct.
/// The analysis identity instead binds the persisted, disambiguated filename
/// and exact normalized source version. Content hash and normalized length
/// remain separate integrity fields so verification errors stay explanatory.
pub(crate) fn stable_source_file_id(file: &SourceFile) -> SourceFileId {
    let mut hasher = StableHasher::new();
    hasher.write(source_filename(file).as_bytes());
    hasher.write_u8(0);
    hasher.write(file.src_hash.to_string().as_bytes());
    hasher.write_u64(u64::from(file.normalized_source_len.to_u32()));
    let fingerprint = hasher.finish::<Fingerprint>();
    let mut encoded = String::from("sniff-test:");
    for byte in fingerprint.to_le_bytes() {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    SourceFileId::new(encoded)
}

/// Why a cached source range could not safely become a rustc span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CachedSourceError {
    SourceUnavailable {
        filename: String,
        kind: io::ErrorKind,
        message: String,
    },
    MissingPermanentSourceSchema {
        schema: String,
    },
    MalformedPermanentSourceFacts {
        reason: String,
    },
    RangeSourceMismatch {
        source: String,
        range: String,
    },
    StableIdentityMismatch {
        expected: String,
        actual: String,
    },
    ContentHashMismatch {
        filename: String,
        expected: String,
        actual: String,
    },
    NormalizedLengthMismatch {
        filename: String,
        expected: u64,
        actual: u64,
    },
    RangeOutOfBounds {
        byte_start: u64,
        byte_end: u64,
        byte_len: u64,
    },
    GlobalPositionOverflow {
        filename: String,
    },
    InvalidSourceRange {
        byte_start: u64,
        byte_end: u64,
    },
}

impl fmt::Display for CachedSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceUnavailable {
                filename, message, ..
            } => write!(
                formatter,
                "cached source `{filename}` is unavailable: {message}"
            ),
            Self::MissingPermanentSourceSchema { schema } => write!(
                formatter,
                "permanent marker source chain is missing required schema `{schema}`"
            ),
            Self::MalformedPermanentSourceFacts { reason } => write!(
                formatter,
                "permanent marker source chain is malformed: {reason}"
            ),
            Self::RangeSourceMismatch { source, range } => write!(
                formatter,
                "cached source range identifies `{range}`, but its source file is `{source}`"
            ),
            Self::StableIdentityMismatch { expected, actual } => write!(
                formatter,
                "cached source identity mismatch: expected `{expected}`, found `{actual}`"
            ),
            Self::ContentHashMismatch {
                filename,
                expected,
                actual,
            } => write!(
                formatter,
                "cached source `{filename}` has content hash `{actual}`, expected `{expected}`"
            ),
            Self::NormalizedLengthMismatch {
                filename,
                expected,
                actual,
            } => write!(
                formatter,
                "cached source `{filename}` has normalized byte length {actual}, expected {expected}"
            ),
            Self::RangeOutOfBounds {
                byte_start,
                byte_end,
                byte_len,
            } => write!(
                formatter,
                "cached source range {byte_start}..{byte_end} is outside byte length {byte_len}"
            ),
            Self::GlobalPositionOverflow { filename } => write!(
                formatter,
                "cached source range for `{filename}` overflows rustc's source map"
            ),
            Self::InvalidSourceRange {
                byte_start,
                byte_end,
            } => write!(
                formatter,
                "cached source range {byte_start}..{byte_end} could not be read from the verified source file"
            ),
        }
    }
}

impl std::error::Error for CachedSourceError {}

impl CachedSourceError {
    fn is_absent_from_disk(&self) -> bool {
        match self {
            Self::SourceUnavailable { filename, .. } => {
                matches!(Path::new(filename).try_exists(), Ok(false))
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use rustc_span::source_map::{FilePathMapping, SourceMap};
    use rustc_span::{BytePos, Pos};
    use tempfile::TempDir;

    use super::{
        CachedSourceError, cached_source_span_in, stable_source_file_id,
        verify_cached_permanent_marker_sources_in,
    };
    use crate::analysis::facts::builder::ArtifactDbBuilder;
    use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
    use crate::analysis::facts::evaluation::DomainId;
    use crate::analysis::facts::human::EvidenceClaimSelector;
    use crate::analysis::facts::human::markers::{
        MarkerClaimEntity, MarkerClaimKey, MarkerOccurrenceEntity, MarkerOccurrenceHasClaim,
        MarkerOccurrenceHasSourceAnchor, MarkerOccurrenceKey,
    };
    use crate::analysis::facts::pack::{AnalysisPack, AnalysisRegistry};
    use crate::analysis::facts::program::{
        SourceAnchorEntity, SourceAnchorInFile, SourceAnchorKey, SourceFileEntity,
    };
    use crate::analysis::facts::schema::RowSchema;
    use crate::analysis::ir::{SourceFileIr, SourceRangeIr};

    #[test]
    fn invalid_source_ranges_render_stable_human_errors() {
        let error = CachedSourceError::InvalidSourceRange {
            byte_start: 4,
            byte_end: 9,
        };

        assert_eq!(
            error.to_string(),
            "cached source range 4..9 could not be read from the verified source file"
        );
    }

    fn write_source(directory: &TempDir, source: &str) -> std::path::PathBuf {
        let path = directory.path().join("cached.rs");
        fs::write(&path, source).expect("write cached source");
        path
    }

    fn source_metadata(path: &Path) -> SourceFileIr {
        let source_map = SourceMap::new(FilePathMapping::empty());
        let file = source_map.load_file(path).expect("load original source");
        SourceFileIr {
            id: stable_source_file_id(&file),
            filename: path.to_string_lossy().into_owned(),
            content_hash: file.src_hash.to_string(),
            byte_len: u64::from(file.normalized_source_len.to_u32()),
        }
    }

    fn range(source: &SourceFileIr, start: u64, end: u64) -> SourceRangeIr {
        SourceRangeIr {
            file: source.id.clone(),
            byte_start: start,
            byte_end: end,
        }
    }

    fn with_session_globals(check: impl FnOnce()) {
        rustc_span::create_default_session_globals_then(check);
    }

    fn permanent_panic_marker_facts(
        source: &SourceFileIr,
    ) -> (
        crate::analysis::facts::encoded::ArtifactFactIr,
        AnalysisRegistry<()>,
    ) {
        permanent_panic_marker_facts_for(&[source])
    }

    fn permanent_panic_marker_facts_for(
        sources: &[&SourceFileIr],
    ) -> (
        crate::analysis::facts::encoded::ArtifactFactIr,
        AnalysisRegistry<()>,
    ) {
        let mut registry = AnalysisRegistry::new();
        CollectedArtifactSchemaPack.register(&mut registry).unwrap();
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }

        for source in sources {
            let file = builder
                .insert_entity(&SourceFileEntity::new(
                    source.id.as_str(),
                    &source.filename,
                    &source.content_hash,
                    source.byte_len,
                ))
                .unwrap();
            let anchor_key = SourceAnchorKey::new(source.id.as_str(), 0, source.byte_len);
            let anchor = builder
                .insert_entity(&SourceAnchorEntity::new(anchor_key.clone()))
                .unwrap();
            builder
                .relate(&anchor, &file, &SourceAnchorInFile::new())
                .unwrap();
            let occurrence_key = MarkerOccurrenceKey::new(anchor_key, None);
            let occurrence = builder
                .insert_entity(&MarkerOccurrenceEntity::new(
                    occurrence_key.clone(),
                    Vec::new(),
                ))
                .unwrap();
            builder
                .relate(
                    &occurrence,
                    &anchor,
                    &MarkerOccurrenceHasSourceAnchor::new(),
                )
                .unwrap();
            let claim = builder
                .insert_entity(&MarkerClaimEntity::new(
                    MarkerClaimKey::new(
                        occurrence_key,
                        DomainId::new("sniff-test.panic").unwrap(),
                        0,
                    ),
                    EvidenceClaimSelector::Unnamed,
                    "expected panic",
                ))
                .unwrap();
            builder
                .relate(&occurrence, &claim, &MarkerOccurrenceHasClaim::new())
                .unwrap();
        }

        let facts = builder.finalize(registry.schemas()).unwrap();
        (facts, registry)
    }

    #[test]
    fn matching_cached_source_returns_a_span_in_the_active_source_map() {
        with_session_globals(|| {
            let directory = tempfile::tempdir().expect("temp directory");
            let path = write_source(&directory, "fn cached() {}\n");
            let source = source_metadata(&path);
            let active = SourceMap::new(FilePathMapping::empty());

            let span =
                cached_source_span_in(&active, &source, &range(&source, 3, 9)).expect("valid span");

            assert_eq!(active.span_to_snippet(span).expect("snippet"), "cached");
        });
    }

    #[test]
    fn cached_source_span_requires_verified_source() {
        with_session_globals(|| {
            let directory = tempfile::tempdir().expect("temp directory");
            let path = write_source(&directory, "fn old() {}\n");
            let source = source_metadata(&path);
            fs::write(&path, "fn new() {}\n").expect("change cached source");
            let active = SourceMap::new(FilePathMapping::empty());

            let error = cached_source_span_in(&active, &source, &range(&source, 3, 6))
                .expect_err("changed source must not produce a span");

            assert!(matches!(
                error,
                CachedSourceError::ContentHashMismatch { .. }
            ));
        });
    }

    #[test]
    fn permanent_panic_marker_rejects_stale_source() {
        with_session_globals(|| {
            let directory = tempfile::tempdir().expect("temp directory");
            let path = write_source(&directory, "// PANIC: expected panic\nfn old() {}\n");
            let source = source_metadata(&path);
            let (facts, registry) = permanent_panic_marker_facts(&source);
            fs::write(&path, "// marker removed\nfn new() {}\n").expect("change cached source");
            let active = SourceMap::new(FilePathMapping::empty());

            let error =
                verify_cached_permanent_marker_sources_in(&active, &facts, registry.schemas())
                    .expect_err("the permanent PANIC marker must reject stale source");

            assert!(matches!(
                error,
                CachedSourceError::ContentHashMismatch { .. }
            ));
        });
    }

    #[test]
    fn permanent_marker_accepts_matching_source() {
        with_session_globals(|| {
            let directory = tempfile::tempdir().expect("temp directory");
            let path = write_source(&directory, "// PANIC: expected panic\nfn cached() {}\n");
            let source = source_metadata(&path);
            let (facts, registry) = permanent_panic_marker_facts(&source);
            let active = SourceMap::new(FilePathMapping::empty());

            verify_cached_permanent_marker_sources_in(&active, &facts, registry.schemas())
                .expect("matching permanent marker source must verify");
        });
    }

    #[test]
    fn permanent_marker_allows_source_that_is_absent_from_disk() {
        with_session_globals(|| {
            let directory = tempfile::tempdir().expect("temp directory");
            let path = write_source(&directory, "// PANIC: expected panic\nfn cached() {}\n");
            let source = source_metadata(&path);
            let (facts, registry) = permanent_panic_marker_facts(&source);
            fs::remove_file(&path).expect("remove dependency source");
            let active = SourceMap::new(FilePathMapping::empty());

            verify_cached_permanent_marker_sources_in(&active, &facts, registry.schemas())
                .expect("an absent dependency source retains the existing fallback policy");
        });
    }

    #[test]
    fn permanent_marker_rejects_every_missing_required_source_chain_table() {
        with_session_globals(|| {
            let directory = tempfile::tempdir().expect("temp directory");
            let path = write_source(&directory, "// PANIC: expected panic\nfn cached() {}\n");
            let source = source_metadata(&path);
            let active = SourceMap::new(FilePathMapping::empty());

            for missing in [
                MarkerOccurrenceEntity::ID,
                MarkerOccurrenceHasSourceAnchor::ID,
                SourceAnchorEntity::ID,
                SourceAnchorInFile::ID,
                SourceFileEntity::ID,
            ] {
                let (mut facts, registry) = permanent_panic_marker_facts(&source);
                facts
                    .tables
                    .retain(|table| table.schema.as_str() != missing);
                facts
                    .relation_index
                    .retain(|relation| relation.relation.schema.as_str() != missing);

                let error =
                    verify_cached_permanent_marker_sources_in(&active, &facts, registry.schemas())
                        .expect_err("missing permanent source-chain tables must fail closed");

                assert!(matches!(
                    error,
                    CachedSourceError::MissingPermanentSourceSchema { .. }
                ));
                assert!(error.to_string().contains(missing));
            }
        });
    }

    #[test]
    fn permanent_marker_rejects_every_missing_required_source_chain_relation() {
        with_session_globals(|| {
            let directory = tempfile::tempdir().expect("temp directory");
            let path = write_source(&directory, "// PANIC: expected panic\nfn cached() {}\n");
            let source = source_metadata(&path);
            let active = SourceMap::new(FilePathMapping::empty());

            for (missing, expected) in [
                (
                    MarkerOccurrenceHasSourceAnchor::ID,
                    "has no physical source anchor",
                ),
                (SourceAnchorInFile::ID, "has no source file"),
            ] {
                let (mut facts, registry) = permanent_panic_marker_facts(&source);
                facts
                    .tables
                    .iter_mut()
                    .find(|table| table.schema.as_str() == missing)
                    .expect("required source-chain relation table")
                    .rows
                    .clear();
                facts
                    .relation_index
                    .retain(|relation| relation.relation.schema.as_str() != missing);

                let error =
                    verify_cached_permanent_marker_sources_in(&active, &facts, registry.schemas())
                        .expect_err(
                            "a marker without its exact source-chain link must fail closed",
                        );

                assert!(matches!(
                    error,
                    CachedSourceError::MalformedPermanentSourceFacts { .. }
                ));
                assert!(error.to_string().contains(expected));
            }
        });
    }

    #[test]
    fn permanent_marker_rejects_duplicate_source_chain_cardinality() {
        with_session_globals(|| {
            let directory = tempfile::tempdir().expect("temp directory");
            let path = write_source(&directory, "// PANIC: expected panic\nfn cached() {}\n");
            let source = source_metadata(&path);
            let active = SourceMap::new(FilePathMapping::empty());

            for (relation_schema, expected) in [
                (
                    MarkerOccurrenceHasSourceAnchor::ID,
                    "multiple physical source anchors",
                ),
                (SourceAnchorInFile::ID, "multiple source files"),
            ] {
                let (mut facts, registry) = permanent_panic_marker_facts(&source);
                let relation_table = facts
                    .tables
                    .iter_mut()
                    .find(|table| table.schema.as_str() == relation_schema)
                    .expect("required source-chain relation table");
                relation_table.rows.push(relation_table.rows[0].clone());
                let mut duplicate = facts
                    .relation_index
                    .iter()
                    .find(|relation| relation.relation.schema.as_str() == relation_schema)
                    .expect("required source-chain relation index")
                    .clone();
                duplicate.relation.row = 1;
                facts.relation_index.push(duplicate);
                facts.relation_index.sort();

                let error =
                    verify_cached_permanent_marker_sources_in(&active, &facts, registry.schemas())
                        .expect_err("duplicate permanent source-chain links must fail closed");

                assert!(error.to_string().contains(expected));
            }
        });
    }

    #[test]
    fn permanent_marker_rejects_a_wrong_valid_physical_anchor_endpoint() {
        with_session_globals(|| {
            let first_directory = tempfile::tempdir().expect("first temp directory");
            let first_path = write_source(
                &first_directory,
                "// PANIC: first expected panic\nfn first() {}\n",
            );
            let second_directory = tempfile::tempdir().expect("second temp directory");
            let second_path = write_source(
                &second_directory,
                "// PANIC: second expected panic\nfn second() {}\n",
            );
            let first = source_metadata(&first_path);
            let second = source_metadata(&second_path);
            let (mut facts, registry) = permanent_panic_marker_facts_for(&[&first, &second]);
            let relation = facts
                .relation_index
                .iter_mut()
                .find(|relation| {
                    relation.relation.schema.as_str() == MarkerOccurrenceHasSourceAnchor::ID
                })
                .expect("marker-anchor relation");
            relation.to.row = u32::from(relation.to.row == 0);
            let active = SourceMap::new(FilePathMapping::empty());

            let error =
                verify_cached_permanent_marker_sources_in(&active, &facts, registry.schemas())
                    .expect_err("an occurrence linked to a wrong valid anchor must fail closed");

            assert!(matches!(
                error,
                CachedSourceError::MalformedPermanentSourceFacts { .. }
            ));
            assert!(
                error
                    .to_string()
                    .contains("does not identify physical source anchor")
            );
        });
    }

    #[test]
    fn permanent_marker_rejects_a_wrong_valid_source_file_endpoint() {
        with_session_globals(|| {
            let first_directory = tempfile::tempdir().expect("first temp directory");
            let first_path = write_source(
                &first_directory,
                "// PANIC: first expected panic\nfn first() {}\n",
            );
            let second_directory = tempfile::tempdir().expect("second temp directory");
            let second_path = write_source(
                &second_directory,
                "// PANIC: second expected panic\nfn second() {}\n",
            );
            let first = source_metadata(&first_path);
            let second = source_metadata(&second_path);
            let (mut facts, registry) = permanent_panic_marker_facts_for(&[&first, &second]);
            let relation = facts
                .relation_index
                .iter_mut()
                .find(|relation| relation.relation.schema.as_str() == SourceAnchorInFile::ID)
                .expect("anchor-file relation");
            relation.to.row = u32::from(relation.to.row == 0);
            let active = SourceMap::new(FilePathMapping::empty());

            let error =
                verify_cached_permanent_marker_sources_in(&active, &facts, registry.schemas())
                    .expect_err("an anchor linked to a wrong valid file must fail closed");

            assert!(matches!(
                error,
                CachedSourceError::MalformedPermanentSourceFacts { .. }
            ));
            assert!(error.to_string().contains("but relation names"));
        });
    }

    #[test]
    fn permanent_marker_rejects_an_out_of_bounds_typed_range() {
        with_session_globals(|| {
            let directory = tempfile::tempdir().expect("temp directory");
            let path = write_source(&directory, "// PANIC: expected panic\nfn cached() {}\n");
            let source = source_metadata(&path);
            let (mut facts, registry) = permanent_panic_marker_facts(&source);
            let file = facts
                .tables
                .iter_mut()
                .find(|table| table.schema.as_str() == SourceFileEntity::ID)
                .expect("source-file table")
                .rows
                .first_mut()
                .expect("source-file row");
            file.data["byte-len"] = serde_json::json!(1);
            let active = SourceMap::new(FilePathMapping::empty());

            let error =
                verify_cached_permanent_marker_sources_in(&active, &facts, registry.schemas())
                    .expect_err("typed source ranges must stay within the recorded byte length");

            assert!(matches!(error, CachedSourceError::RangeOutOfBounds { .. }));
        });
    }

    #[test]
    fn source_identity_distinguishes_versions_at_the_same_filename() {
        with_session_globals(|| {
            let directory = tempfile::tempdir().expect("temp directory");
            let path = write_source(&directory, "fn old() {}\n");
            let old = source_metadata(&path);
            fs::write(&path, "fn new() {}\n").expect("replace source at the same path");
            let new = source_metadata(&path);

            assert_ne!(
                old.id, new.id,
                "composed caches must not alias different source versions that share a path"
            );
        });
    }

    #[test]
    fn missing_cached_source_returns_a_nonfatal_unavailable_error() {
        with_session_globals(|| {
            let directory = tempfile::tempdir().expect("temp directory");
            let path = directory.path().join("missing.rs");
            let source = SourceFileIr {
                id: crate::analysis::ir::SourceFileId::new("rustc:missing"),
                filename: path.to_string_lossy().into_owned(),
                content_hash: String::from("md5=00000000000000000000000000000000"),
                byte_len: 1,
            };
            let active = SourceMap::new(FilePathMapping::empty());

            let error = cached_source_span_in(&active, &source, &range(&source, 0, 1))
                .expect_err("missing source must not produce a span");

            assert!(matches!(
                error,
                CachedSourceError::SourceUnavailable {
                    kind: std::io::ErrorKind::NotFound,
                    ..
                }
            ));
        });
    }

    #[test]
    fn source_unavailable_is_ignorable_only_when_the_recorded_path_is_absent() {
        let directory = tempfile::tempdir().expect("temp directory");
        let existing = write_source(&directory, "fn present() {}\n");
        let missing = directory.path().join("missing.rs");
        let error_for = |path: &Path| CachedSourceError::SourceUnavailable {
            filename: path.to_string_lossy().into_owned(),
            kind: std::io::ErrorKind::NotFound,
            message: String::from("test source-map reload failure"),
        };

        assert!(
            !error_for(&existing).is_absent_from_disk(),
            "a source-map reload failure must not hide a changed file that still exists"
        );
        assert!(
            error_for(&missing).is_absent_from_disk(),
            "truly unavailable dependency source may safely degrade to cached marker facts"
        );
    }

    #[test]
    fn utf8_ranges_use_rustc_normalized_crlf_byte_offsets() {
        with_session_globals(|| {
            let directory = tempfile::tempdir().expect("temp directory");
            let path = write_source(&directory, "α\r\nlet β = 1;\r\n");
            let source = source_metadata(&path);
            let normalized = "α\nlet β = 1;\n";
            let start = normalized.find('β').expect("beta offset") as u64;
            let end = start + 'β'.len_utf8() as u64;
            let active = SourceMap::new(FilePathMapping::empty());

            let span = cached_source_span_in(&active, &source, &range(&source, start, end))
                .expect("normalized UTF-8 span");
            let loaded = active.lookup_source_file(span.lo());

            assert_eq!(active.span_to_snippet(span).expect("snippet"), "β");
            assert_eq!(
                span.lo(),
                loaded.start_pos + BytePos(u32::try_from(start).expect("test offset fits u32"))
            );
            assert_eq!(
                span.hi(),
                loaded.start_pos + BytePos(u32::try_from(end).expect("test offset fits u32"))
            );
            assert_eq!(source.byte_len, normalized.len() as u64);
        });
    }
}
