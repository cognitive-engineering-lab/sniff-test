//! Built-in panic and safety effect definitions and rustc detection passes.
#![feature(rustc_private)]
#![deny(warnings)]
#![warn(clippy::pedantic)]

extern crate rustc_abi;
extern crate rustc_ast;
extern crate rustc_data_structures;
extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

pub mod panic;
pub mod safety;

use sniff_test_core::artifact::EffectKey;
use sniff_test_core::config::{EffectConfig, SniffTestConfig};
use sniff_test_core::effects::{Effect, EffectSelection, EffectSpec, effect};
use std::collections::BTreeMap;

#[must_use]
/// Return defaults for every built-in effect.
///
/// # Panics
///
/// Panics if two built-in effects register the same name.
pub fn registered_effect_configs() -> BTreeMap<String, EffectConfig> {
    let defaults = [
        (panic::Panic::EFFECT_NAME, panic::Panic::default_config()),
        (
            safety::Safety::EFFECT_NAME,
            safety::Safety::default_config(),
        ),
    ];
    let count = defaults.len();
    let configs = defaults
        .into_iter()
        .map(|(name, config)| (name.to_owned(), config))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(configs.len(), count, "effect names must be unique");
    configs
}

#[must_use]
pub fn registered_keys() -> Vec<EffectKey> {
    vec![
        EffectKey::new(panic::Panic::EFFECT_NAME),
        EffectKey::new(safety::Safety::EFFECT_NAME),
    ]
}

#[must_use]
pub fn selected_effect_objects<'config>(
    selection: &EffectSelection,
    config: &'config SniffTestConfig,
) -> Vec<Box<dyn Effect + 'config>> {
    [
        effect::<panic::Panic>(config.effect(panic::Panic::EFFECT_NAME)),
        effect::<safety::Safety>(config.effect(safety::Safety::EFFECT_NAME)),
    ]
    .into_iter()
    .filter(|effect| selection.selects(effect.key()))
    .collect()
}
