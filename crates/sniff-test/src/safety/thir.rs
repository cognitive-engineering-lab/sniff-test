//! THIR-based unsafe-operation detection.
//!
//! The operation set and detection rules mirror rustc's THIR unsafety checker
//! (`rustc_mir_build/src/check_unsafety.rs` in the pinned toolchain; rustc
//! line references appear in comments so toolchain-bump diffs stay
//! mechanical). rustc's checker owns the definition of "operation that
//! requires `unsafe`"; this pass reuses those rules with a different sink:
//! every detected operation needs a nearby `// SAFETY:` justification, inside
//! or outside an `unsafe` block. Unsafe blocks only anchor where
//! justification comments attach, and compiler-generated (`BuiltinUnsafe`)
//! blocks suppress findings entirely — their unsafety is the compiler's
//! obligation, not the user's.
//!
//! Reading THIR in `after_analysis` requires `-Zno-steal-thir`, which the
//! driver appends to every rustc invocation.

use std::ops::Bound;

use rustc_abi::{FieldIdx, VariantIdx};
use rustc_ast::AsmMacro;
use rustc_data_structures::stack::ensure_sufficient_stack;
use rustc_hir::def::DefKind;
use rustc_hir::def_id::LocalDefId;
use rustc_hir::{self as hir, BindingMode, ByRef, Mutability};
use rustc_middle::middle::codegen_fn_attrs::TargetFeature;
use rustc_middle::mir::BorrowKind;
use rustc_middle::thir::visit::{self, Visitor};
use rustc_middle::thir::{
    Block, BlockSafety, Expr, ExprId, ExprKind, InlineAsmExpr, Pat, PatKind, Thir,
};
use rustc_middle::ty::{self, Ty, TyCtxt};
use rustc_span::Span;

use super::{
    SafetyAnalysis, SafetyCall, SafetyCallKind, SafetyCallee, SafetyFinding, SafetyOpKind,
    missing_safety_requirements, safety_doc_summary,
};
use crate::config::{LintLevel, SafetyConfig};
use crate::source_markers::{SafetySatisfaction, span_safety_satisfactions};

pub(super) fn collect_body_findings(
    tcx: TyCtxt<'_>,
    owner: LocalDefId,
    config: &SafetyConfig,
    ambiguous_obligations: LintLevel,
    analysis: &mut SafetyAnalysis,
) {
    let Ok((thir, root)) = tcx.thir_body(owner) else {
        return;
    };
    let thir = thir.borrow();
    let mut safety_scopes = Vec::new();
    let mut visitor = UnsafeOpVisitor {
        tcx,
        thir: &thir,
        owner,
        config,
        ambiguous_obligations,
        body_target_features: &tcx.body_codegen_attrs(owner.to_def_id()).target_features,
        typing_env: ty::TypingEnv::non_body_analysis(tcx, owner),
        assignment_info: None,
        in_union_destructure: false,
        inside_adt: false,
        builtin_unsafe_depth: 0,
        safety_scopes: &mut safety_scopes,
        analysis,
    };
    // Params can contain unsafe patterns, such as union destructuring
    // (check_unsafety.rs:1191).
    for param in &thir.params {
        if let Some(pat) = param.pat.as_deref() {
            visitor.visit_pat(pat);
        }
    }
    visitor.visit_expr(&thir[root]);
}

struct UnsafeOpVisitor<'a, 'tcx> {
    tcx: TyCtxt<'tcx>,
    thir: &'a Thir<'tcx>,
    /// The body owner findings are attributed to; the closure's own def id
    /// inside closure bodies.
    owner: LocalDefId,
    config: &'a SafetyConfig,
    ambiguous_obligations: LintLevel,
    body_target_features: &'tcx [TargetFeature],
    typing_env: ty::TypingEnv<'tcx>,
    /// Type of the assignment LHS while visiting it; a write-only union field
    /// access is safe (check_unsafety.rs:38-39).
    assignment_info: Option<Ty<'tcx>>,
    in_union_destructure: bool,
    inside_adt: bool,
    /// Depth of compiler-generated unsafe blocks. Findings are suppressed
    /// inside them: `.await` and similar desugarings perform unsafe calls the
    /// user cannot justify and does not need to.
    builtin_unsafe_depth: usize,
    /// `// SAFETY:` satisfactions of the enclosing user unsafe blocks. Shared
    /// with inner bodies so closures inherit enclosing scopes lexically.
    safety_scopes: &'a mut Vec<Vec<SafetySatisfaction>>,
    analysis: &'a mut SafetyAnalysis,
}

impl<'a, 'tcx> UnsafeOpVisitor<'a, 'tcx> {
    fn unsafe_op(&mut self, span: Span, op: SafetyOpKind) {
        if self.builtin_unsafe_depth > 0 {
            return;
        }
        if self.applicable_satisfactions(span).is_empty() {
            self.analysis
                .findings
                .push(SafetyFinding::OpMissingJustification {
                    caller: self.owner.to_def_id(),
                    op,
                    span,
                });
        }
    }

    fn unsafe_call(&mut self, span: Span, call: SafetyCall) {
        if self.builtin_unsafe_depth > 0 {
            return;
        }
        if self.ignores_callee(call.callee) {
            return;
        }
        let satisfactions = self.applicable_satisfactions(span);

        if let SafetyCallee::Def(def_id) = call.callee {
            self.analysis.push_ambiguous_requirement_names(
                self.tcx,
                def_id,
                self.ambiguous_obligations,
            );
            let summary = safety_doc_summary(self.tcx, def_id);
            if !summary.requirements.is_empty() {
                if self.ambiguous_obligations.is_deny()
                    && !summary.ambiguous_requirements.is_empty()
                {
                    return;
                }
                let missing = missing_safety_requirements(
                    &summary.requirements,
                    &summary.ambiguous_requirements,
                    &satisfactions,
                    self.ambiguous_obligations,
                );
                if !missing.is_empty() {
                    self.analysis
                        .findings
                        .push(SafetyFinding::CallMissingRequirements {
                            caller: self.owner.to_def_id(),
                            callee: call.callee,
                            call_kind: call.kind,
                            span,
                            missing_requirements: missing,
                        });
                }
                return;
            }
        }

        if satisfactions.is_empty() {
            self.analysis
                .findings
                .push(SafetyFinding::CallMissingJustification {
                    caller: self.owner.to_def_id(),
                    callee: call.callee,
                    call_kind: call.kind,
                    span,
                });
        }
    }

    fn ignores_callee(&self, callee: SafetyCallee) -> bool {
        matches!(callee, SafetyCallee::Def(def_id) if self.config.ignores_def(self.tcx, def_id))
    }

    fn applicable_satisfactions(&self, span: Span) -> Vec<SafetySatisfaction> {
        self.safety_scopes
            .iter()
            .flat_map(|scope| scope.iter().cloned())
            .chain(span_safety_satisfactions(self.tcx, span))
            .collect()
    }

    /// The `// SAFETY:` comment sits above the `unsafe` keyword, which only
    /// the enclosing block expression's span includes.
    fn unsafe_block_span(&self, hir_id: hir::HirId, block_span: Span) -> Span {
        match self.tcx.parent_hir_node(hir_id) {
            hir::Node::Expr(expr) => expr.span,
            _ => block_span,
        }
    }

    /// Closures, coroutines, and inline consts are visited with their
    /// enclosing body so scopes flow into them (check_unsafety.rs:185-224).
    fn visit_inner_body(&mut self, def: LocalDefId) {
        let Ok((inner_thir, root)) = self.tcx.thir_body(def) else {
            return;
        };
        let inner_thir = inner_thir.borrow();
        let mut inner = UnsafeOpVisitor {
            tcx: self.tcx,
            thir: &inner_thir,
            owner: def,
            config: self.config,
            ambiguous_obligations: self.ambiguous_obligations,
            body_target_features: self.body_target_features,
            typing_env: self.typing_env,
            assignment_info: self.assignment_info,
            in_union_destructure: false,
            inside_adt: false,
            builtin_unsafe_depth: self.builtin_unsafe_depth,
            safety_scopes: &mut *self.safety_scopes,
            analysis: &mut *self.analysis,
        };
        for param in &inner_thir.params {
            if let Some(pat) = param.pat.as_deref() {
                inner.visit_pat(pat);
            }
        }
        inner.visit_expr(&inner_thir[root]);
    }

    /// Whether a pattern inside a union destructuring reads the field
    /// (check_unsafety.rs:304-330).
    fn union_destructure_reads_field(&mut self, pat: &'a Pat<'tcx>) -> bool {
        match pat.kind {
            PatKind::Missing => unreachable!(),
            // binding to a variable allows getting stuff out of variable
            PatKind::Binding { .. }
            // match is conditional on having this value
            | PatKind::Constant { .. }
            | PatKind::Variant { .. }
            | PatKind::Leaf { .. }
            | PatKind::Deref { .. }
            | PatKind::DerefPattern { .. }
            | PatKind::Range { .. }
            | PatKind::Slice { .. }
            | PatKind::Array { .. }
            | PatKind::Guard { .. }
            // Never constitutes a witness of uninhabitedness.
            | PatKind::Never => {
                self.unsafe_op(pat.span, SafetyOpKind::AccessToUnionField);
                true
            }
            // wildcard doesn't read anything; the others just wrap patterns
            // that the caller recurses on.
            PatKind::Wild | PatKind::Or { .. } | PatKind::Error(_) => false,
        }
    }

    /// Unsafe-fn and target-feature call detection, plus the tool's
    /// configured-obligation policy (check_unsafety.rs:470-517).
    fn check_call(&mut self, expr: &'a Expr<'tcx>, fun: ExprId) {
        let fn_ty = self.thir[fun].ty;
        let sig = fn_ty.fn_sig(self.tcx);
        let (callee_features, safe_target_features): (&[_], _) = match *fn_ty.kind() {
            ty::FnDef(func_id, ..) => {
                let cg_attrs = self.tcx.codegen_fn_attrs(func_id);
                (&cg_attrs.target_features, cg_attrs.safe_target_features)
            }
            _ => (&[], false),
        };
        if sig.safety().is_unsafe() && !safe_target_features {
            let callee = if let ty::FnDef(func_id, _) = fn_ty.kind() {
                SafetyCallee::Def(*func_id)
            } else {
                SafetyCallee::FunctionPointer
            };
            self.unsafe_call(
                expr.span,
                SafetyCall {
                    callee,
                    kind: SafetyCallKind::Unsafe,
                },
            );
        } else if let &ty::FnDef(func_id, _) = fn_ty.kind() {
            if !self
                .tcx
                .is_target_feature_call_safe(callee_features, self.body_target_features)
            {
                // A call to a safe `#[target_feature]` function still
                // requires unsafe when the caller lacks the features.
                self.unsafe_call(
                    expr.span,
                    SafetyCall {
                        callee: SafetyCallee::Def(func_id),
                        kind: SafetyCallKind::Unsafe,
                    },
                );
            } else if self.config.marks_safety_obligation_def(self.tcx, func_id) {
                self.unsafe_call(
                    expr.span,
                    SafetyCall {
                        callee: SafetyCallee::Def(func_id),
                        kind: SafetyCallKind::ConfiguredObligation,
                    },
                );
            }
        }
    }

    /// Raw borrows of derefs and union fields are safe; recurse on the rest
    /// (check_unsafety.rs:519-546).
    fn check_raw_borrow(&mut self, arg: ExprId) {
        if let ExprKind::Scope { value: arg, .. } = self.thir[arg].kind
            && let ExprKind::Deref { arg } = self.thir[arg].kind
        {
            // Taking a raw ref to a deref place expr is always safe. Make
            // sure the expression we're deref'ing is safe, though.
            visit::walk_expr(self, &self.thir[arg]);
            return;
        }

        let mut peeled = arg;
        while let ExprKind::Scope { value: arg, .. } = self.thir[peeled].kind
            && let ExprKind::Field { lhs, .. } = self.thir[arg].kind
            && let ty::Adt(def, _) = &self.thir[lhs].ty.kind()
            && def.is_union()
        {
            peeled = lhs;
        }
        visit::walk_expr(self, &self.thir[peeled]);
    }

    // check_unsafety.rs:562-608
    fn check_inline_asm(&mut self, expr: &'a Expr<'tcx>, asm: &'a InlineAsmExpr<'tcx>) {
        // `naked_asm!` forms one atomic unit of unsafety with its `#[naked]`
        // attribute and needs no unsafe block itself.
        if matches!(asm.asm_macro, AsmMacro::Asm) {
            self.unsafe_op(expr.span, SafetyOpKind::InlineAssembly);
        }

        for op in &*asm.operands {
            use rustc_middle::thir::InlineAsmOperand::{
                Const, In, InOut, Label, Out, SplitInOut, SymFn, SymStatic,
            };
            match op {
                In { expr, .. }
                | Out {
                    expr: Some(expr), ..
                }
                | InOut { expr, .. } => self.visit_expr(&self.thir[*expr]),
                SplitInOut {
                    in_expr, out_expr, ..
                } => {
                    self.visit_expr(&self.thir[*in_expr]);
                    if let Some(out_expr) = out_expr {
                        self.visit_expr(&self.thir[*out_expr]);
                    }
                }
                Out { expr: None, .. } | Const { .. } | SymFn { .. } | SymStatic { .. } => {}
                // Label blocks are ordinary safe code.
                Label { block } => visit::walk_block(self, &self.thir[*block]),
            }
        }
    }

    /// Mutable/extern static and raw-pointer dereferences
    /// (check_unsafety.rs:546-561).
    fn check_deref(&mut self, expr: &'a Expr<'tcx>, arg: ExprId) {
        if let ExprKind::StaticRef { def_id, .. } | ExprKind::ThreadLocalRef(def_id) =
            self.thir[arg].kind
        {
            if self.tcx.is_mutable_static(def_id) {
                self.unsafe_op(expr.span, SafetyOpKind::UseOfMutableStatic);
            } else if self.tcx.is_foreign_item(def_id) {
                match self.tcx.def_kind(def_id) {
                    DefKind::Static {
                        safety: hir::Safety::Safe,
                        ..
                    } => {}
                    _ => self.unsafe_op(expr.span, SafetyOpKind::UseOfExternStatic),
                }
            }
        } else if self.thir[arg].ty.is_raw_ptr() {
            self.unsafe_op(expr.span, SafetyOpKind::DerefRawPointer);
        }
    }

    /// Layout-constrained mutation plus the union write-only special case;
    /// returns true when the whole assignment has already been visited
    /// (check_unsafety.rs:652-671).
    fn check_assignment(&mut self, expr: &'a Expr<'tcx>, lhs: ExprId, rhs: ExprId) -> bool {
        let lhs = &self.thir[lhs];
        // First, check whether we are mutating a layout constrained field.
        let mut visitor = LayoutConstrainedPlaceVisitor::new(self.thir, self.tcx);
        visit::walk_expr(&mut visitor, lhs);
        if visitor.found {
            self.unsafe_op(expr.span, SafetyOpKind::MutationOfLayoutConstrainedField);
        }

        // Second, check for accesses to union fields. AssignOp reads *and*
        // writes the LHS, so it gets no special handling.
        if matches!(expr.kind, ExprKind::Assign { .. }) {
            self.assignment_info = Some(lhs.ty);
            visit::walk_expr(self, lhs);
            self.assignment_info = None;
            visit::walk_expr(self, &self.thir[rhs]);
            return true;
        }
        false
    }

    // check_unsafety.rs:633-651
    fn check_field(
        &mut self,
        expr: &'a Expr<'tcx>,
        lhs: ExprId,
        variant_index: VariantIdx,
        name: FieldIdx,
    ) {
        let lhs = &self.thir[lhs];
        if let ty::Adt(adt_def, _) = lhs.ty.kind() {
            if adt_def.variant(variant_index).fields[name]
                .safety
                .is_unsafe()
            {
                self.unsafe_op(expr.span, SafetyOpKind::UseOfUnsafeField);
            } else if adt_def.is_union() {
                if self.assignment_info.is_some() {
                    // Write-only assignment to a union field is safe; union
                    // fields that need dropping are rejected during
                    // wf-checking.
                } else {
                    self.unsafe_op(expr.span, SafetyOpKind::AccessToUnionField);
                }
            }
        }
    }
}

impl<'a, 'tcx> Visitor<'a, 'tcx> for UnsafeOpVisitor<'a, 'tcx> {
    fn thir(&self) -> &'a Thir<'tcx> {
        self.thir
    }

    // check_unsafety.rs:272-301
    fn visit_block(&mut self, block: &'a Block) {
        match block.safety_mode {
            BlockSafety::BuiltinUnsafe => {
                self.builtin_unsafe_depth += 1;
                visit::walk_block(self, block);
                self.builtin_unsafe_depth -= 1;
            }
            BlockSafety::ExplicitUnsafe(hir_id) => {
                let span = self.unsafe_block_span(hir_id, block.span);
                self.safety_scopes
                    .push(span_safety_satisfactions(self.tcx, span));
                visit::walk_block(self, block);
                self.safety_scopes
                    .pop()
                    .expect("unsafe block scope should be present");
            }
            BlockSafety::Safe => {
                visit::walk_block(self, block);
            }
        }
    }

    // check_unsafety.rs:303-398
    fn visit_pat(&mut self, pat: &'a Pat<'tcx>) {
        if self.in_union_destructure && self.union_destructure_reads_field(pat) {
            return; // we can return here since this already requires unsafe
        }

        match &pat.kind {
            PatKind::Leaf { subpatterns, .. } => {
                if let ty::Adt(adt_def, ..) = pat.ty.kind() {
                    for pat in subpatterns {
                        if adt_def.non_enum_variant().fields[pat.field]
                            .safety
                            .is_unsafe()
                        {
                            self.unsafe_op(pat.pattern.span, SafetyOpKind::UseOfUnsafeField);
                        }
                    }
                    if adt_def.is_union() {
                        let old_in_union_destructure =
                            std::mem::replace(&mut self.in_union_destructure, true);
                        visit::walk_pat(self, pat);
                        self.in_union_destructure = old_in_union_destructure;
                    } else if (Bound::Unbounded, Bound::Unbounded)
                        != self.tcx.layout_scalar_valid_range(adt_def.did())
                    {
                        let old_inside_adt = std::mem::replace(&mut self.inside_adt, true);
                        visit::walk_pat(self, pat);
                        self.inside_adt = old_inside_adt;
                    } else {
                        visit::walk_pat(self, pat);
                    }
                } else {
                    visit::walk_pat(self, pat);
                }
            }
            PatKind::Variant {
                adt_def,
                args: _,
                variant_index,
                subpatterns,
            } => {
                for pat in subpatterns {
                    let field = &pat.field;
                    if adt_def.variant(*variant_index).fields[*field]
                        .safety
                        .is_unsafe()
                    {
                        self.unsafe_op(pat.pattern.span, SafetyOpKind::UseOfUnsafeField);
                    }
                }
                visit::walk_pat(self, pat);
            }
            PatKind::Binding {
                mode: BindingMode(ByRef::Yes(_, rm), _),
                ty,
                ..
            } => {
                if self.inside_adt
                    && let ty::Ref(_, ty, _) = ty.kind()
                {
                    match rm {
                        Mutability::Not => {
                            if !ty.is_freeze(self.tcx, self.typing_env) {
                                self.unsafe_op(
                                    pat.span,
                                    SafetyOpKind::BorrowOfLayoutConstrainedField,
                                );
                            }
                        }
                        Mutability::Mut => {
                            self.unsafe_op(
                                pat.span,
                                SafetyOpKind::MutationOfLayoutConstrainedField,
                            );
                        }
                    }
                }
                visit::walk_pat(self, pat);
            }
            PatKind::Deref { .. } | PatKind::DerefPattern { .. } => {
                let old_inside_adt = std::mem::replace(&mut self.inside_adt, false);
                visit::walk_pat(self, pat);
                self.inside_adt = old_inside_adt;
            }
            _ => {
                visit::walk_pat(self, pat);
            }
        }
    }

    // check_unsafety.rs:400-692
    fn visit_expr(&mut self, expr: &'a Expr<'tcx>) {
        // Reset assignment tracking unless this expression keeps us within the
        // same place. rustc exhaustively lists the resetting variants
        // (check_unsafety.rs:401-461); the wildcard here trades that review
        // pressure for resilience to new expression kinds.
        match expr.kind {
            ExprKind::Field { .. }
            | ExprKind::VarRef { .. }
            | ExprKind::UpvarRef { .. }
            | ExprKind::Scope { .. }
            | ExprKind::Cast { .. } => {}
            _ => self.assignment_info = None,
        }

        match expr.kind {
            ExprKind::Scope { value, .. } => {
                // Lint-level tracking via hir_id is not needed here.
                ensure_sufficient_stack(|| {
                    self.visit_expr(&self.thir[value]);
                });
                return; // don't visit the whole expression
            }
            // check_unsafety.rs:470-517, plus the configured-obligation policy.
            ExprKind::Call { fun, .. } => {
                self.check_call(expr, fun);
            }
            // check_unsafety.rs:519-546
            ExprKind::RawBorrow { arg, .. } => {
                self.check_raw_borrow(arg);
                return;
            }
            // check_unsafety.rs:546-561
            ExprKind::Deref { arg } => {
                self.check_deref(expr, arg);
            }
            // check_unsafety.rs:562-608
            ExprKind::InlineAsm(ref asm)
                if matches!(asm.asm_macro, AsmMacro::Asm | AsmMacro::NakedAsm) =>
            {
                self.check_inline_asm(expr, asm);
                return;
            }
            // check_unsafety.rs:609-625
            ExprKind::Adt(ref adt) => {
                if adt.adt_def.variant(adt.variant_index).has_unsafe_fields() {
                    self.unsafe_op(expr.span, SafetyOpKind::InitializingTypeWithUnsafeField);
                }
                match self.tcx.layout_scalar_valid_range(adt.adt_def.did()) {
                    (Bound::Unbounded, Bound::Unbounded) => {}
                    _ => {
                        self.unsafe_op(expr.span, SafetyOpKind::InitializingLayoutConstrainedType);
                    }
                }
            }
            ExprKind::Closure(ref closure) => {
                self.visit_inner_body(closure.closure_id);
            }
            ExprKind::ConstBlock { did, args: _ } => {
                self.visit_inner_body(did.expect_local());
            }
            // check_unsafety.rs:633-651
            ExprKind::Field {
                lhs,
                variant_index,
                name,
            } => {
                self.check_field(expr, lhs, variant_index, name);
            }
            // check_unsafety.rs:652-671; the guard runs the checks and says
            // whether the assignment subtree was already fully visited. A
            // false guard falls through to the wildcard arm's ordinary walk.
            ExprKind::Assign { lhs, rhs } | ExprKind::AssignOp { lhs, rhs, .. }
                if self.check_assignment(expr, lhs, rhs) =>
            {
                return;
            }
            // check_unsafety.rs:672-687
            ExprKind::Borrow { borrow_kind, arg } => {
                let mut visitor = LayoutConstrainedPlaceVisitor::new(self.thir, self.tcx);
                visit::walk_expr(&mut visitor, expr);
                if visitor.found {
                    match borrow_kind {
                        BorrowKind::Fake(_) | BorrowKind::Shared
                            if !self.thir[arg].ty.is_freeze(self.tcx, self.typing_env) =>
                        {
                            self.unsafe_op(expr.span, SafetyOpKind::BorrowOfLayoutConstrainedField);
                        }
                        BorrowKind::Mut { .. } => {
                            self.unsafe_op(
                                expr.span,
                                SafetyOpKind::MutationOfLayoutConstrainedField,
                            );
                        }
                        BorrowKind::Fake(_) | BorrowKind::Shared => {}
                    }
                }
            }
            ExprKind::PlaceUnwrapUnsafeBinder { .. }
            | ExprKind::ValueUnwrapUnsafeBinder { .. }
            | ExprKind::WrapUnsafeBinder { .. } => {
                self.unsafe_op(expr.span, SafetyOpKind::UnsafeBinderCast);
            }
            _ => {}
        }
        visit::walk_expr(self, expr);
    }
}

/// Searches for accesses to layout constrained fields
/// (check_unsafety.rs:227-266).
struct LayoutConstrainedPlaceVisitor<'a, 'tcx> {
    found: bool,
    thir: &'a Thir<'tcx>,
    tcx: TyCtxt<'tcx>,
}

impl<'a, 'tcx> LayoutConstrainedPlaceVisitor<'a, 'tcx> {
    fn new(thir: &'a Thir<'tcx>, tcx: TyCtxt<'tcx>) -> Self {
        Self {
            found: false,
            thir,
            tcx,
        }
    }
}

impl<'a, 'tcx> Visitor<'a, 'tcx> for LayoutConstrainedPlaceVisitor<'a, 'tcx> {
    fn thir(&self) -> &'a Thir<'tcx> {
        self.thir
    }

    fn visit_expr(&mut self, expr: &'a Expr<'tcx>) {
        match expr.kind {
            ExprKind::Field { lhs, .. } => {
                if let ty::Adt(adt_def, _) = self.thir[lhs].ty.kind()
                    && (Bound::Unbounded, Bound::Unbounded)
                        != self.tcx.layout_scalar_valid_range(adt_def.did())
                {
                    self.found = true;
                }
                visit::walk_expr(self, expr);
            }
            // Keep walking only while we stay in the same place: scope
            // wrappers and rustc's `ExprCategory::Place` expression kinds.
            ExprKind::Scope { .. }
            | ExprKind::Index { .. }
            | ExprKind::UpvarRef { .. }
            | ExprKind::VarRef { .. }
            | ExprKind::PlaceTypeAscription { .. }
            | ExprKind::ValueTypeAscription { .. }
            | ExprKind::PlaceUnwrapUnsafeBinder { .. }
            | ExprKind::ValueUnwrapUnsafeBinder { .. } => {
                visit::walk_expr(self, expr);
            }
            // Everything else — including a dereference — leaves the place.
            _ => {}
        }
    }
}
