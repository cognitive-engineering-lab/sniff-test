//! Policy-neutral safety fact extraction.
//!
//! Operation detection lives in the `thir` submodule and mirrors rustc's own
//! unsafety checker. This module records raw calls, unsafe operations, and
//! source-level unsafe scopes; lint policy and contract interpretation belong
//! to the typed safety evaluation pipeline.

mod thir;

use rustc_hir::def::DefKind;
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
pub(crate) struct SafetyEffectGroup {
    pub(crate) id: usize,
    pub(crate) span: Span,
}

/// Policy-neutral identity for operations that share one source-level unsafe
/// scope. The numeric identity is stable only within one collection run; the
/// span is the source anchor for that group.
pub(crate) type RawSafetyEffectGroup = SafetyEffectGroup;

/// One runtime operation that rustc requires to occur in an unsafe context.
///
/// `owner` is the exact THIR body owner. Operations in nested closures retain
/// the closure's `DefId`, even though collection is seeded from local
/// functions and associated functions. Consumers whose IR only models those
/// outer items must explicitly attach or remap closure-owned facts.
#[derive(Debug, Clone)]
pub(crate) struct RawSafetyOpFact {
    pub(crate) owner: DefId,
    pub(crate) op: SafetyOpKind,
    pub(crate) span: Span,
    pub(crate) marker_anchor_spans: Vec<Span>,
    pub(crate) effect_group: RawSafetyEffectGroup,
}

/// One THIR call site that can participate in safety interpretation.
///
/// The call's unsafe/obligation meaning is deliberately absent: extraction
/// records only its source-level effect group, while the interpreter combines
/// call metadata and the active safety policy later.
#[derive(Debug, Clone)]
pub(crate) struct RawSafetyCallFact {
    pub(crate) owner: DefId,
    /// Callee identity normalized to the declared trait item when applicable.
    /// Desugared expressions such as `value?` can contain several calls with
    /// one exact span, so this identity joins THIR calls to MIR reachability
    /// edges after MIR resolves a concrete impl.
    pub(crate) callee: Option<DefId>,
    /// THIR callee retained for source-contract interpretation.
    ///
    /// Unlike [`Self::callee`], a direct impl call remains an impl method and
    /// unresolved generic or dynamic dispatch remains a trait method. A trait
    /// item whose impl is statically selected is omitted so the resolved impl's
    /// contract remains authoritative.
    pub(crate) source_callee: Option<DefId>,
    /// The call occurs inside a compiler-generated `BuiltinUnsafe` block.
    /// rustc treats that unsafe context as the compiler's responsibility, so
    /// the call must not become a user-facing safety obligation.
    pub(crate) inside_builtin_unsafe: bool,
    /// Artifact-local identity of this THIR source call. Compiler-generated
    /// branches with the same owner, exact span, callee, and unsafe context
    /// reuse this identity, as do derived reachability endpoints for an
    /// indirect call.
    pub(crate) call_site: usize,
    /// Exact THIR call span, including expansion context. Source-callsite
    /// ranges alone can collapse two macro expansions onto the same text.
    pub(crate) span: Span,
    pub(crate) effect_group: RawSafetyEffectGroup,
}

/// One source-level unsafe scope, including scopes with no direct THIR
/// operation and scopes inherited lexically by a nested closure body.
#[derive(Debug, Clone)]
pub(crate) struct RawSafetyGroupFact {
    pub(crate) owner: DefId,
    pub(crate) effect_group: RawSafetyEffectGroup,
}

/// Policy-neutral safety facts collected in one THIR walk.
#[derive(Debug, Default)]
pub(crate) struct RawSafetyFacts {
    pub(crate) groups: Vec<RawSafetyGroupFact>,
    pub(crate) calls: Vec<RawSafetyCallFact>,
    pub(crate) operations: Vec<RawSafetyOpFact>,
}

impl PartialEq for SafetyEffectGroup {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for SafetyEffectGroup {}

impl std::hash::Hash for SafetyEffectGroup {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// Collects call grouping and unsafe-operation facts for every analyzable
/// local function and associated function body without applying safety policy.
pub(crate) fn collect_raw_safety_facts(tcx: TyCtxt<'_>) -> RawSafetyFacts {
    thir::collect_raw_safety_facts(tcx)
}

/// Normalizes an impl method to the trait item named by THIR.
///
/// MIR reachability resolves trait calls to concrete impl methods, while THIR
/// retains the declared trait method. Both identify the same source call for
/// safety grouping.
#[must_use]
pub(crate) fn call_identity_def_id(tcx: TyCtxt<'_>, def_id: DefId) -> DefId {
    tcx.trait_item_of(def_id).unwrap_or(def_id)
}

/// Non-call operations that require `unsafe`, mirroring the non-call variants
/// of rustc's `UnsafeOpKind` (`rustc_mir_build/src/check_unsafety.rs`).
///
/// The variant set is pinned to the toolchain in rust-toolchain.toml; diff it
/// against rustc's enum on toolchain bumps. The `unsafe_ops*` fixtures cover
/// one operation per variant as a behavioral canary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SafetyOpKind {
    #[serde(rename = "raw-pointer-dereference")]
    DerefRawPointer,
    #[serde(rename = "mutable-static-access")]
    UseOfMutableStatic,
    #[serde(rename = "extern-static-access")]
    UseOfExternStatic,
    #[serde(rename = "union-field-access")]
    AccessToUnionField,
    #[serde(rename = "unsafe-field-access")]
    UseOfUnsafeField,
    #[serde(rename = "layout-constrained-type-initialization")]
    InitializingLayoutConstrainedType,
    #[serde(rename = "unsafe-field-initialization")]
    InitializingTypeWithUnsafeField,
    #[serde(rename = "layout-constrained-field-mutation")]
    MutationOfLayoutConstrainedField,
    #[serde(rename = "layout-constrained-field-borrow")]
    BorrowOfLayoutConstrainedField,
    InlineAssembly,
    UnsafeBinderCast,
}

impl SafetyOpKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::DerefRawPointer => "raw pointer dereference",
            Self::UseOfMutableStatic => "mutable static access",
            Self::UseOfExternStatic => "extern static access",
            Self::AccessToUnionField => "union field access",
            Self::UseOfUnsafeField => "unsafe field access",
            Self::InitializingLayoutConstrainedType => "layout-constrained type initialization",
            Self::InitializingTypeWithUnsafeField => "unsafe field initialization",
            Self::MutationOfLayoutConstrainedField => "layout-constrained field mutation",
            Self::BorrowOfLayoutConstrainedField => "layout-constrained field borrow",
            Self::InlineAssembly => "inline assembly",
            Self::UnsafeBinderCast => "unsafe binder cast",
        }
    }
}

#[must_use]
pub(crate) fn fn_def_is_unsafe(tcx: TyCtxt<'_>, def_id: DefId) -> bool {
    matches!(tcx.def_kind(def_id), DefKind::Fn | DefKind::AssocFn)
        && tcx
            .fn_sig(def_id)
            .instantiate_identity()
            .skip_binder()
            .safety()
            .is_unsafe()
}

#[cfg(test)]
mod tests {
    use super::SafetyOpKind;

    #[test]
    fn safety_op_kinds_have_stable_user_facing_names() {
        let cases = [
            (SafetyOpKind::DerefRawPointer, "raw-pointer-dereference"),
            (SafetyOpKind::UseOfMutableStatic, "mutable-static-access"),
            (SafetyOpKind::UseOfExternStatic, "extern-static-access"),
            (SafetyOpKind::AccessToUnionField, "union-field-access"),
            (SafetyOpKind::UseOfUnsafeField, "unsafe-field-access"),
            (
                SafetyOpKind::InitializingLayoutConstrainedType,
                "layout-constrained-type-initialization",
            ),
            (
                SafetyOpKind::InitializingTypeWithUnsafeField,
                "unsafe-field-initialization",
            ),
            (
                SafetyOpKind::MutationOfLayoutConstrainedField,
                "layout-constrained-field-mutation",
            ),
            (
                SafetyOpKind::BorrowOfLayoutConstrainedField,
                "layout-constrained-field-borrow",
            ),
            (SafetyOpKind::InlineAssembly, "inline-assembly"),
            (SafetyOpKind::UnsafeBinderCast, "unsafe-binder-cast"),
        ];

        for (kind, expected) in cases {
            let serialized = serde_json::to_string(&kind).expect("serialize safety op kind");
            assert_eq!(serialized, format!("\"{expected}\""));
            assert_eq!(
                serde_json::from_str::<SafetyOpKind>(&serialized).expect("deserialize safety op"),
                kind
            );
        }
    }
}
