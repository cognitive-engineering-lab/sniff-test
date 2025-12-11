use regex::Regex;
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use rustc_span::source_map::{Spanned, respan};

use crate::{
    ARGS,
    annotations::{AnnotationSource, Condition, DocStrSource, PropertyViolation},
};

pub fn violation_from_text(
    def_id: DefId,
    text: &str,
    source: &AnnotationSource,
    source2: &DocStrSource,
    tcx: TyCtxt,
) -> PropertyViolation {
    match try_parse_conditions(text, source2) {
        Ok(Some(conditions)) => {
            log::warn!("{def_id:?} conditions {conditions:?}");
            PropertyViolation::Conditionally(conditions)
        }
        Ok(None) => {
            log::debug!("couldn't determine conditional property violation for {def_id:?}");
            if (def_id.is_local() || ARGS.lock().unwrap().as_ref().unwrap().check_dependencies)
                && ARGS.lock().unwrap().as_ref().unwrap().fine_grained
            {
                let msg = format!(
                    "couldn't determine conditional property violation for {def_id:?} from {source:?} based on text {text:?}",
                );
                match source {
                    AnnotationSource::DocComment(span) => {
                        tcx.dcx().struct_span_err(span.clone(), msg).emit()
                    }
                    AnnotationSource::TomlOverride => tcx.dcx().struct_err(msg).emit(),
                };
                panic!("see above error");
            }
            PropertyViolation::Unconditional
        }
        Err(err_msg) => {
            // Only show errors in the current crate and if we're fine-grained.
            // Otherwise, malformed sniff-test conditions are just interpreted as general violation.
            if (def_id.is_local() || ARGS.lock().unwrap().as_ref().unwrap().check_dependencies)
                && ARGS.lock().unwrap().as_ref().unwrap().fine_grained
            {
                let msg = format!(
                    "malformed conditional property violation for {def_id:?} from {source:?}: {err_msg}",
                );
                match source {
                    AnnotationSource::DocComment(span) => {
                        tcx.dcx().struct_span_err(span.clone(), msg).emit()
                    }
                    AnnotationSource::TomlOverride => tcx.dcx().struct_err(msg).emit(),
                };
                panic!("see above error");
            } else {
                PropertyViolation::Unconditional
            }
        }
    }
}

fn try_parse_conditions(
    text: &str,
    doc_str_src: &DocStrSource,
) -> Result<Option<Vec<Spanned<Condition>>>, String> {
    // Match bullet points at start of line (after optional whitespace)
    let bullet_regex = Regex::new(r"(?m)^\s*[-*]\s+").unwrap();

    let mut conditions = Vec::new();
    let matches: Vec<_> = bullet_regex.find_iter(text).collect();

    if matches.is_empty() {
        return Ok(None);
    }

    for i in 0..matches.len() {
        let start = matches[i].end();
        let end = if i + 1 < matches.len() {
            matches[i + 1].start()
        } else {
            text.len()
        };

        let bullet_content = text[start..end].trim();

        // Split on first colon to get name and description
        let (name, description) = bullet_content
            .split_once(':')
            .ok_or_else(|| format!("bullet item missing colon separator: '{bullet_content}'"))?;

        let name = name.trim();
        let description = description.trim();

        // Validate that name is a single word (no spaces)
        if name.is_empty() {
            return Err(format!("bullet item has empty name: '{bullet_content}'"));
        }

        if name.contains(char::is_whitespace) {
            return Err(format!(
                "bullet item name must be a single word, found: '{name}'",
            ));
        }

        if description.is_empty() {
            return Err(format!("bullet item '{name}' has empty description"));
        }

        conditions.push(respan(
            doc_str_src.src_span(start..end).unwrap_or_default(),
            Condition {
                name: name.to_owned(),
                description: description.to_owned(),
            },
        ));
    }

    if conditions.is_empty() {
        Ok(None)
    } else {
        Ok(Some(conditions))
    }
}
