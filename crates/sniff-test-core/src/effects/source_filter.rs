//! Interpretation-time selection of effect sources by their owning crate.

use std::collections::BTreeMap;

use crate::artifact::FunctionId;
use crate::config::AnalysisConfig;

/// Crate identity and names available while interpreting one workspace unit.
pub struct SourceFilterContext<'a> {
    pub reporting_crate_id: u64,
    pub crate_names: &'a BTreeMap<u64, String>,
}

/// A manifest-derived predicate shared by concrete and documented seeds.
pub struct EffectSourceFilter<'a> {
    selected: Option<&'a [String]>,
}

impl<'a> EffectSourceFilter<'a> {
    #[must_use]
    pub fn from_config(config: &'a AnalysisConfig) -> Self {
        Self {
            selected: config.source_crates.as_deref(),
        }
    }

    #[must_use]
    pub fn is_restricted(&self) -> bool {
        self.selected.is_some()
    }

    #[must_use]
    pub fn allows(&self, source: FunctionId, context: &SourceFilterContext<'_>) -> bool {
        let Some(selected) = self.selected else {
            return true;
        };
        let crate_id = source.def_path_hash.stable_crate_id();
        selected.iter().any(|name| {
            if name == "crate" {
                crate_id == context.reporting_crate_id
            } else {
                context
                    .crate_names
                    .get(&crate_id)
                    .is_some_and(|actual| actual == name)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{EffectSourceFilter, SourceFilterContext};
    use crate::artifact::{FunctionId, StableDefPathHash};
    use crate::config::AnalysisConfig;
    use std::collections::BTreeMap;

    fn function(crate_id: u64) -> FunctionId {
        let hash =
            serde_json::from_str::<StableDefPathHash>(&format!("\"{crate_id:016x}{:016x}\"", 1))
                .expect("stable function hash");
        FunctionId::generic(hash)
    }

    #[test]
    fn omitted_and_selected_crates_use_identity_and_rust_crate_names() {
        let names = BTreeMap::from([
            (1, String::from("app")),
            (2, String::from("dep_crate")),
            (3, String::from("app")),
        ]);
        let context = SourceFilterContext {
            reporting_crate_id: 1,
            crate_names: &names,
        };
        let mut config = AnalysisConfig::default();
        let filter = EffectSourceFilter::from_config(&config);
        assert!(filter.allows(function(1), &context));
        assert!(filter.allows(function(2), &context));
        config.source_crates = Some(vec![String::from("crate")]);
        let filter = EffectSourceFilter::from_config(&config);
        assert!(filter.allows(function(1), &context));
        assert!(!filter.allows(function(3), &context));
        assert!(!filter.allows(function(2), &context));
        config.source_crates = Some(vec![String::from("dep_crate")]);
        let filter = EffectSourceFilter::from_config(&config);
        assert!(filter.allows(function(2), &context));
        assert!(!filter.allows(function(1), &context));
        config.source_crates = Some(Vec::new());
        assert!(!EffectSourceFilter::from_config(&config).allows(function(1), &context));
    }
}
