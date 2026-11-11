//! Current editor destinations, kept separate from the analyzer's recorded facts.
use super::*;

#[derive(Debug, Clone, Serialize)]
pub struct NavigationLocation {
    #[serde(flatten)]
    pub location: Location,
    pub approximate: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FindingNavigation {
    pub source: Option<NavigationLocation>,
    pub root: Option<NavigationLocation>,
    pub contract: Option<NavigationLocation>,
    pub trace: Vec<Option<NavigationLocation>>,
}

impl FindingNavigation {
    fn from_finding(finding: &Finding) -> Self {
        let Some(audit) = &finding.audit else {
            return Self::default();
        };
        let wrap = |location: &Location| NavigationLocation {
            location: location.clone(),
            approximate: false,
        };
        Self {
            source: audit.source.as_ref().map(wrap),
            root: audit.root.as_ref().map(wrap),
            contract: audit.contract.as_ref().map(wrap),
            trace: audit
                .trace
                .iter()
                .map(|step| step.location.as_ref().map(wrap))
                .collect(),
        }
    }

    fn locations(&mut self) -> impl Iterator<Item = &mut NavigationLocation> {
        self.source
            .iter_mut()
            .chain(self.root.iter_mut())
            .chain(self.contract.iter_mut())
            .chain(self.trace.iter_mut().filter_map(Option::as_mut))
    }
}

impl Session {
    pub fn finding_navigation(&self, id: &str) -> Option<FindingNavigation> {
        self.navigation
            .get(id)
            .cloned()
            .or_else(|| self.finding(id).map(FindingNavigation::from_finding))
    }

    pub(super) fn map_saved_locations(&mut self, path: &str, previous: &str, content: &str) {
        let mapping = EditMap::new(previous, content);
        for finding in &mut self.analysis.findings {
            let navigation = self
                .navigation
                .entry(finding.id.clone())
                .or_insert_with(|| FindingNavigation::from_finding(finding));
            for destination in navigation.locations() {
                if destination.location.path == path {
                    destination.approximate |= mapping.map(&mut destination.location, false);
                }
            }
            if let Some(audit) = &mut finding.audit {
                for target in &mut audit.targets {
                    if target.location.path == path {
                        mapping.map(&mut target.location, true);
                    }
                }
            }
        }
    }
}

/// One byte-based change map with strict attachment and tolerant navigation policies.
struct EditMap<'a> {
    previous: &'a str,
    content: &'a str,
    old_hash: String,
    new_hash: String,
    edits: Vec<(usize, usize, usize)>,
}

impl<'a> EditMap<'a> {
    fn new(previous: &'a str, content: &'a str) -> Self {
        let diff = similar::TextDiff::configure()
            .timeout(std::time::Duration::from_millis(100))
            .diff_chars(previous, content);
        let (mut old_offset, mut new_offset) = (0, 0);
        let mut pending = None;
        let mut edits = Vec::new();
        for change in diff.iter_all_changes() {
            let bytes = change.value().len();
            match change.tag() {
                similar::ChangeTag::Equal => {
                    if let Some((start, inserted_at)) = pending.take() {
                        edits.push((start, old_offset, new_offset - inserted_at));
                    }
                    old_offset += bytes;
                    new_offset += bytes;
                }
                similar::ChangeTag::Delete => {
                    pending.get_or_insert((old_offset, new_offset));
                    old_offset += bytes;
                }
                similar::ChangeTag::Insert => {
                    pending.get_or_insert((old_offset, new_offset));
                    new_offset += bytes;
                }
            }
        }
        if let Some((start, inserted_at)) = pending {
            edits.push((start, old_offset, new_offset - inserted_at));
        }
        Self {
            previous,
            content,
            old_hash: content_hash(previous.as_bytes()),
            new_hash: content_hash(content.as_bytes()),
            edits,
        }
    }

    /// Returns whether a tolerant destination overlaps an edit. Strict targets
    /// become unavailable on overlap; no mapped navigation grants editing rights.
    fn map(&self, location: &mut Location, strict: bool) -> bool {
        if !location.available || location.hash != self.old_hash {
            return false;
        }
        if self.previous.get(location.start..location.end).is_none() {
            location.available = false;
            return false;
        }
        let mut approximate = false;
        for &(start, end, inserted) in self.edits.iter().rev() {
            if location.start >= end {
                location.start = start + inserted + (location.start - end);
                location.end = start + inserted + (location.end - end);
            } else if location.end > start {
                if strict {
                    location.available = false;
                    return false;
                }
                approximate = true;
                let fully_replaced = location.start >= start && location.end <= end;
                location.start = location.start.min(start);
                location.end = if fully_replaced {
                    location.start
                } else if location.end >= end {
                    start + inserted + (location.end - end)
                } else {
                    start + inserted
                };
            }
        }
        location.start = boundary(self.content, location.start);
        location.end = boundary(self.content, location.end).max(location.start);
        location.hash = self.new_hash.clone();
        approximate
    }
}

fn boundary(source: &str, offset: usize) -> usize {
    let mut offset = offset.min(source.len());
    while !source.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

#[cfg(test)]
mod tests {
    use super::*;

    fn location(source: &str, needle: &str) -> Location {
        let start = source.find(needle).unwrap();
        Location {
            path: "test.rs".into(),
            source_id: "source".into(),
            hash: content_hash(source.as_bytes()),
            start,
            end: start + needle.len(),
            available: true,
        }
    }

    #[test]
    fn maps_exact_ranges_through_unicode_crlf_edits_and_undo() {
        let original = "fn work() {\r\n    effect();\r\n}\r\n";
        let edited = format!("// λ 🦀\r\n{original}// tail\r\n");
        let mut target = location(original, "effect()");
        assert!(!EditMap::new(original, &edited).map(&mut target, false));
        assert_eq!(&edited[target.start..target.end], "effect()");
        assert_eq!(target.hash, content_hash(edited.as_bytes()));
        assert!(!EditMap::new(&edited, original).map(&mut target, false));
        assert_eq!(target, location(original, "effect()"));
    }

    #[test]
    fn overlapping_edits_keep_navigation_but_invalidate_edit_targets() {
        let original = "fn work() { effect(); }";
        for edited in ["fn work() { changed(); }", "fn work() {  }", ""] {
            let mut navigation = location(original, "effect()");
            let mut strict = navigation.clone();
            let mapping = EditMap::new(original, edited);
            assert!(mapping.map(&mut navigation, false));
            mapping.map(&mut strict, true);
            assert!(navigation.available);
            assert!(edited.get(navigation.start..navigation.end).is_some());
            assert_eq!(navigation.hash, content_hash(edited.as_bytes()));
            assert!(!strict.available);
        }
    }

    #[test]
    fn deleted_site_collapses_to_nearest_surviving_position() {
        let original = "fn work() { effect(); next(); }";
        let edited = "fn work() { next(); }";
        let mut navigation = location(original, "effect(); ");
        assert!(EditMap::new(original, edited).map(&mut navigation, false));
        assert_eq!(navigation.start, navigation.end);
        assert_eq!(navigation.start, edited.find("next()").unwrap());
    }

    #[test]
    fn mismatched_or_unavailable_locations_are_not_resurrected() {
        let mut target = location("fn effect() {}", "effect");
        let original = target.clone();
        assert!(!EditMap::new("different", "edited").map(&mut target, false));
        assert_eq!(target, original);
        target.available = false;
        EditMap::new("fn effect() {}", "").map(&mut target, false);
        assert!(!target.available);
    }
}
