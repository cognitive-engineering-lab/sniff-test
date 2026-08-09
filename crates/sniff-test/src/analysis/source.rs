//! Verified integration of cached source locations with rustc's active source map.
//!
//! Cached filenames are only hints for locating source. A span is returned
//! after the loaded file's stable identity, content hash, normalized byte
//! length, and requested byte range all match the artifact IR.

use std::collections::BTreeSet;
use std::fmt;
use std::hash::Hasher;
use std::io;
use std::path::Path;

use rustc_data_structures::{fingerprint::Fingerprint, stable_hasher::StableHasher};
use rustc_middle::ty::TyCtxt;
use rustc_span::source_map::SourceMap;
use rustc_span::{BytePos, Pos, SourceFile, Span};

use super::ir::{ArtifactAnalysisIr, SourceFileId, SourceFileIr, SourceRangeIr};

/// Verifies every available source file that contributed ordinary comment
/// markers to cached IR.
///
/// rustc's SVH intentionally ignores ordinary comments, while sniff-test's
/// `// PANIC:` and `// SAFETY:` markers affect interpretation. A matching SVH
/// therefore cannot by itself prove that a sidecar still matches a marker-
/// bearing source file. Source whose recorded path is absent remains trusted
/// as part of the exact sidecar; every failure for an existing path rejects the
/// stale marker facts.
pub(crate) fn verify_cached_marker_sources(
    tcx: TyCtxt<'_>,
    ir: &ArtifactAnalysisIr,
) -> Result<(), CachedSourceError> {
    let mut checked = BTreeSet::new();
    for range in ir.functions.iter().flat_map(|body| {
        body.markers
            .iter()
            .filter_map(|marker| marker.source_range.as_ref().or(body.source_range.as_ref()))
    }) {
        if !checked.insert(range.file.clone()) {
            continue;
        }
        let source = ir
            .source_files
            .binary_search_by(|source| source.id.cmp(&range.file))
            .ok()
            .map(|index| &ir.source_files[index])
            .ok_or_else(|| CachedSourceError::MissingSourceIdentity {
                identity: range.file.as_str().to_owned(),
            })?;
        match cached_source_span(tcx, source, range) {
            Ok(_) => {}
            Err(error) if error.is_absent_from_disk() => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
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
    // Prefer an existing SourceFile to avoid loading a duplicate. The analysis
    // identity is independent of rustc's exporting-crate identity, so loading
    // a verified dependency or sysroot file below is also valid.
    let existing = {
        let files = source_map.files();
        files
            .iter()
            .find(|file| stable_source_file_id(file) == source.id)
            .cloned()
    };
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
    MissingSourceIdentity {
        identity: String,
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
            Self::MissingSourceIdentity { identity } => write!(
                formatter,
                "cached source identity `{identity}` is absent from the artifact IR"
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

    use super::{CachedSourceError, cached_source_span_in, stable_source_file_id};
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
