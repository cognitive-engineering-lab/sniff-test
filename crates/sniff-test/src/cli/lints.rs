//! Rust-scoped lint levels for effect obligations.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use rustc_hir::def::DefKind;
use rustc_hir::def_id::LocalDefId;
use rustc_lint_defs::LintExpectationId;
use rustc_middle::ty::TyCtxt;
use rustc_session::lint::{Level, Lint};
use sniff_test_core::config::LintLevel;
use sniff_test_core::namespace::canonical_namespace;

pub(super) struct RegisteredEffectLint {
    pub effect: String,
    pub attribute_name: String,
    pub lint: &'static Lint,
}

/// Register every effect under its Rust-identifier spelling.
pub(super) fn registered_effect_lints() -> &'static [RegisteredEffectLint] {
    static LINTS: OnceLock<Vec<RegisteredEffectLint>> = OnceLock::new();
    LINTS.get_or_init(|| {
        let mut names = BTreeSet::new();
        sniff_test_effects::registered_keys()
            .into_iter()
            .map(|effect| {
                let attribute_name = effect.as_str().replace('-', "_");
                assert!(
                    names.insert(attribute_name.clone()),
                    "effect lint names must be unique"
                );
                let name = Box::leak(format!("sniff_test::{attribute_name}").into_boxed_str());
                let lint = Box::leak(Box::new(Lint {
                    name,
                    default_level: Level::Allow,
                    desc: "unmet effect obligations reachable from this function",
                    is_externally_loaded: true,
                    ..Lint::default_fields_for_macro()
                }));
                RegisteredEffectLint {
                    effect: effect.as_str().to_owned(),
                    attribute_name,
                    lint,
                }
            })
            .collect()
    })
}

pub(super) struct ItemLintSelection {
    pub roots: Vec<LocalDefId>,
    pub levels: BTreeMap<(String, String), LintLevel>,
    pub expectations: Vec<ItemExpectation>,
}

pub(super) struct ItemExpectation {
    pub root: String,
    pub effect: String,
    pub id: LintExpectationId,
}

pub(super) fn collect_item_lints(tcx: TyCtxt<'_>) -> ItemLintSelection {
    let mut selection = ItemLintSelection {
        roots: Vec::new(),
        levels: BTreeMap::new(),
        expectations: Vec::new(),
    };
    let registered = registered_effect_lints();
    for local in tcx.hir_body_owners() {
        if !matches!(tcx.def_kind(local), DefKind::Fn | DefKind::AssocFn) {
            continue;
        }
        let mut selected = BTreeSet::new();
        let mut ancestor = Some(local.to_def_id());
        while let Some(def_id) = ancestor {
            let Some(owner) = def_id.as_local() else {
                break;
            };
            let owner_hir_id = tcx.local_def_id_to_hir_id(owner);
            for attr in tcx.hir_attrs(owner_hir_id).iter().filter(|attr| {
                attr.name().is_some_and(|name| {
                    matches!(
                        name.as_str(),
                        "allow" | "warn" | "deny" | "forbid" | "expect"
                    )
                })
            }) {
                let Some(items) = attr.meta_item_list() else {
                    continue;
                };
                for item in &items {
                    let Some(meta) = item.meta_item() else {
                        continue;
                    };
                    let segments = &meta.path.segments;
                    if segments.len() != 2 || segments[0].ident.name.as_str() != "sniff_test" {
                        continue;
                    }
                    if let Some(effect_lint) = registered
                        .iter()
                        .find(|entry| entry.attribute_name == segments[1].ident.name.as_str())
                    {
                        selected.insert(effect_lint.effect.as_str());
                    }
                }
            }
            ancestor = tcx.opt_parent(def_id);
        }
        if selected.is_empty() {
            continue;
        }
        selection.roots.push(local);
        let path = canonical_namespace(tcx, local.to_def_id());
        let hir_id = tcx.local_def_id_to_hir_id(local);
        for effect in selected {
            let lint = registered
                .iter()
                .find(|entry| entry.effect == effect)
                .expect("selected effect lint was registered");
            let lint_level = tcx.lint_level_at_node(lint.lint, hir_id);
            if lint_level.level == Level::Expect
                && let Some(id) = lint_level.lint_id
            {
                selection.expectations.push(ItemExpectation {
                    root: path.clone(),
                    effect: effect.to_owned(),
                    id,
                });
            }
            let level = match lint_level.level {
                Level::Allow | Level::Expect => LintLevel::Allow,
                Level::Warn | Level::ForceWarn => LintLevel::Warn,
                Level::Deny | Level::Forbid => LintLevel::Deny,
            };
            selection
                .levels
                .insert((path.clone(), effect.to_owned()), level);
        }
    }
    selection
}

/// Fulfill only expectations for effects with an unmet finding at this item.
pub(super) fn fulfill_item_expectations(
    tcx: TyCtxt<'_>,
    expectations: &[ItemExpectation],
    findings: &[sniff_test_diagnostics::findings::Finding],
) {
    let mut fulfilled = Vec::new();
    for expectation in expectations {
        if fulfilled.contains(&expectation.id) {
            continue;
        }
        if findings.iter().any(|finding| {
            finding.unmet_item_effect().is_some_and(|(root, effect)| {
                root == expectation.root && effect == expectation.effect
            })
        }) {
            tcx.dcx()
                .struct_expect("fulfilled sniff-test effect expectation", expectation.id)
                .emit();
            fulfilled.push(expectation.id);
        }
    }
}
