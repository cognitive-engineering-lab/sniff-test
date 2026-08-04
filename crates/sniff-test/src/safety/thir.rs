//! THIR-based unsafe-operation detection.
//!
//! The operation set and detection rules mirror rustc's THIR unsafety checker
//! (`rustc_mir_build/src/check_unsafety.rs` in the pinned toolchain; rustc
//! line references appear in comments so toolchain-bump diffs stay
//! mechanical). rustc's checker owns the definition of "operation that
//! requires `unsafe`"; this pass reuses those rules to record raw artifact IR
//! facts. Unsafe blocks anchor source-level effect groups. Non-call operations
//! in compiler-generated (`BuiltinUnsafe`) blocks are excluded, while calls are
//! retained with a suppression fact because their unsafety is the compiler's
//! obligation rather than a user-code effect.
//!
//! Reading THIR in `after_analysis` requires `-Zno-steal-thir`, which the
//! driver appends to every rustc invocation.

use std::collections::HashSet;
use std::ops::Bound;

use rustc_abi::{FieldIdx, VariantIdx};
use rustc_ast::AsmMacro;
use rustc_data_structures::stack::ensure_sufficient_stack;
use rustc_hir::def::DefKind;
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_hir::{self as hir, BindingMode, ByRef, Mutability};
use rustc_middle::mir::BorrowKind;
use rustc_middle::thir::visit::{self, Visitor};
use rustc_middle::thir::{
    Block, BlockSafety, Expr, ExprId, ExprKind, InlineAsmExpr, Pat, PatKind, Thir,
};
use rustc_middle::ty::{self, Instance, InstanceKind, Ty, TyCtxt};
use rustc_span::Span;

use super::{
    RawSafetyCallFact, RawSafetyFacts, RawSafetyGroupFact, RawSafetyOpFact, SafetyEffectGroup,
    SafetyOpKind, call_identity_def_id,
};

pub(super) fn collect_raw_safety_facts(tcx: TyCtxt<'_>) -> RawSafetyFacts {
    let mut sink = RawSafetyFactSink::default();
    for owner in tcx
        .hir_body_owners()
        .filter(|owner| matches!(tcx.def_kind(*owner), DefKind::Fn | DefKind::AssocFn))
    {
        collect_body(tcx, owner, &mut sink);
    }
    sink.into_facts()
}

fn collect_body(tcx: TyCtxt<'_>, owner: LocalDefId, sink: &mut RawSafetyFactSink) {
    let Ok((thir, root)) = tcx.thir_body(owner) else {
        return;
    };
    let thir = thir.borrow();
    let mut safety_scopes = Vec::new();
    let mut effect_groups = Vec::new();
    let mut visitor = UnsafeOpVisitor {
        tcx,
        thir: &thir,
        owner,
        typing_env: ty::TypingEnv::non_body_analysis(tcx, owner),
        assignment_info: None,
        in_union_destructure: false,
        inside_adt: false,
        builtin_unsafe_depth: 0,
        safety_scopes: &mut safety_scopes,
        effect_groups: &mut effect_groups,
        sink,
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

#[derive(Default)]
struct RawSafetyFactSink {
    facts: RawSafetyFacts,
    call_identities: HashSet<RawCallIdentity>,
    group_identities: HashSet<(DefId, SafetyEffectGroup)>,
    next_effect_group: usize,
    next_call_site: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RawCallIdentity {
    owner: DefId,
    callee: Option<DefId>,
    source_callee: Option<DefId>,
    span: Span,
    enclosing_group: Option<SafetyEffectGroup>,
    inside_builtin_unsafe: bool,
}

impl RawSafetyFactSink {
    fn new_effect_group(&mut self, span: Span) -> SafetyEffectGroup {
        let group = SafetyEffectGroup {
            id: self.next_effect_group,
            span,
        };
        self.next_effect_group += 1;
        group
    }

    fn into_facts(self) -> RawSafetyFacts {
        self.facts
    }

    fn new_safety_scope(&mut self, owner: DefId, span: Span) -> SafetyEffectGroup {
        let effect_group = self.new_effect_group(span);
        self.group_identities.insert((owner, effect_group));
        self.facts.groups.push(RawSafetyGroupFact {
            owner,
            effect_group,
        });
        effect_group
    }

    fn inherit_effect_scopes(&mut self, owner: DefId, inherited: &[SafetyEffectGroup]) {
        for effect_group in inherited {
            if self.group_identities.insert((owner, *effect_group)) {
                self.facts.groups.push(RawSafetyGroupFact {
                    owner,
                    effect_group: *effect_group,
                });
            }
        }
    }

    fn record_call(
        &mut self,
        owner: DefId,
        callee: Option<DefId>,
        source_callee: Option<DefId>,
        span: Span,
        active_group: Option<SafetyEffectGroup>,
        inside_builtin_unsafe: bool,
    ) {
        let identity = RawCallIdentity {
            owner,
            callee,
            source_callee,
            span,
            enclosing_group: active_group,
            inside_builtin_unsafe,
        };
        // Derive and desugaring expansion can lower multiple control-flow
        // branches from one compiler-generated source expression. MIR
        // reachability canonicalizes those branches by owner, span, and
        // callee, so retain that same source identity in the THIR facts.
        if !self.call_identities.insert(identity) {
            return;
        }
        let effect_group = active_group.unwrap_or_else(|| self.new_effect_group(span));
        self.facts.calls.push(RawSafetyCallFact {
            owner,
            callee,
            source_callee,
            inside_builtin_unsafe,
            call_site: self.next_call_site,
            span,
            effect_group,
        });
        self.next_call_site += 1;
    }

    fn record_operation(
        &mut self,
        owner: DefId,
        span: Span,
        op: SafetyOpKind,
        marker_anchor_spans: Vec<Span>,
        active_group: Option<SafetyEffectGroup>,
    ) {
        let effect_group = active_group.unwrap_or_else(|| self.new_effect_group(span));
        self.facts.operations.push(RawSafetyOpFact {
            owner,
            op,
            span,
            marker_anchor_spans,
            effect_group,
        });
    }
}

struct SafetyScope {
    marker_span: Span,
}

struct UnsafeOpVisitor<'a, 'tcx> {
    tcx: TyCtxt<'tcx>,
    thir: &'a Thir<'tcx>,
    /// The body owner findings are attributed to; the closure's own def id
    /// inside closure bodies.
    owner: LocalDefId,
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
    /// `// SAFETY:` markers on enclosing user unsafe blocks. Shared with inner
    /// bodies so closures inherit enclosing scopes lexically.
    safety_scopes: &'a mut Vec<SafetyScope>,
    effect_groups: &'a mut Vec<SafetyEffectGroup>,
    sink: &'a mut RawSafetyFactSink,
}

impl<'a, 'tcx> UnsafeOpVisitor<'a, 'tcx> {
    fn unsafe_op(&mut self, span: Span, op: SafetyOpKind) {
        if self.builtin_unsafe_depth > 0 {
            return;
        }
        self.sink.record_operation(
            self.owner.to_def_id(),
            span,
            op,
            self.applicable_marker_spans(span),
            self.effect_groups.last().copied(),
        );
    }

    fn record_call(&mut self, callee: Option<DefId>, source_callee: Option<DefId>, span: Span) {
        self.sink.record_call(
            self.owner.to_def_id(),
            callee,
            source_callee,
            span,
            self.effect_groups.last().copied(),
            self.builtin_unsafe_depth > 0,
        );
    }

    /// Keeps the declared trait method only while dispatch remains unresolved.
    ///
    /// THIR can name the trait item for both `T::method()` and a statically
    /// selected call such as `Wrapper::<T>::method()`. Generic arguments alone
    /// cannot distinguish those cases. Instance resolution can: an unresolved
    /// bound returns no instance, dynamic dispatch returns `Virtual`, and a
    /// selected impl returns its concrete item.
    fn source_call_callee(
        &self,
        def_id: DefId,
        args: ty::GenericArgsRef<'tcx>,
        identity: DefId,
    ) -> Option<DefId> {
        if identity != def_id || self.tcx.trait_of_assoc(def_id).is_none() {
            return Some(def_id);
        }
        let typing_env = ty::TypingEnv::post_analysis(self.tcx, self.owner);
        match Instance::try_resolve(self.tcx, typing_env, def_id, args) {
            Ok(
                None
                | Some(Instance {
                    def: InstanceKind::Virtual(..),
                    ..
                }),
            )
            | Err(_) => Some(def_id),
            Ok(Some(_)) => None,
        }
    }

    fn applicable_marker_spans(&self, span: Span) -> Vec<Span> {
        let mut spans = self
            .safety_scopes
            .iter()
            .map(|scope| scope.marker_span)
            .collect::<Vec<_>>();
        spans.push(span);
        spans
    }

    /// The `// SAFETY:` comment sits above the `unsafe` keyword, which only
    /// the enclosing block expression's span includes.
    fn unsafe_block_span(&self, hir_id: hir::HirId, block_span: Span) -> Span {
        match self.tcx.parent_hir_node(hir_id) {
            hir::Node::Expr(expr) => expr.span,
            _ => block_span,
        }
    }

    /// Closures and coroutines are runtime code and inherit the enclosing
    /// source-level justification scopes.
    fn visit_inner_body(&mut self, def: LocalDefId) {
        let Ok((inner_thir, root)) = self.tcx.thir_body(def) else {
            return;
        };
        let inner_thir = inner_thir.borrow();
        self.sink
            .inherit_effect_scopes(def.to_def_id(), self.effect_groups);
        let mut inner = UnsafeOpVisitor {
            tcx: self.tcx,
            thir: &inner_thir,
            owner: def,
            typing_env: self.typing_env,
            assignment_info: self.assignment_info,
            in_union_destructure: false,
            inside_adt: false,
            builtin_unsafe_depth: self.builtin_unsafe_depth,
            safety_scopes: &mut *self.safety_scopes,
            effect_groups: &mut *self.effect_groups,
            sink: &mut *self.sink,
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

    /// Retains every statically known call plus unsafe function-pointer calls.
    ///
    /// Extraction deliberately does not decide whether a known call represents
    /// an unsafe call or a documented safety obligation. The interpreter makes
    /// that decision from the call edge and active policy.
    fn check_call(&mut self, expr: &'a Expr<'tcx>, fun: ExprId) {
        let fn_ty = self.thir[fun].ty;
        let sig = fn_ty.fn_sig(self.tcx);
        if sig.safety().is_unsafe() || matches!(fn_ty.kind(), ty::FnDef(..)) {
            let (callee, source_callee) = match fn_ty.kind() {
                ty::FnDef(def_id, args) => {
                    let identity = call_identity_def_id(self.tcx, *def_id);
                    let source_callee = self.source_call_callee(*def_id, args, identity);
                    (Some(identity), source_callee)
                }
                _ => (None, None),
            };
            self.record_call(callee, source_callee, expr.span);
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
                let group = self.sink.new_safety_scope(self.owner.to_def_id(), span);
                self.effect_groups.push(group);
                self.safety_scopes.push(SafetyScope { marker_span: span });
                visit::walk_block(self, block);
                self.safety_scopes
                    .pop()
                    .expect("unsafe block scope should be present");
                self.effect_groups
                    .pop()
                    .expect("unsafe block effect group should be present");
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
            // check_unsafety.rs:470-517, plus the documented-obligation policy.
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
            // Compile-time inline-const effects are outside the runtime
            // effect graph tracked by sniff-test.
            ExprKind::ConstBlock { .. } => return,
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

#[cfg(test)]
mod tests {
    use rustc_hir::def_id::CRATE_DEF_ID;
    use rustc_span::{BytePos, Span};

    use super::RawSafetyFactSink;
    use crate::safety::SafetyOpKind;

    fn span(start: u32, end: u32) -> Span {
        Span::with_root_ctxt(BytePos(start), BytePos(end))
    }

    #[test]
    fn raw_sink_records_calls_and_operations_without_safety_policy() {
        let owner = CRATE_DEF_ID.to_def_id();
        let scope_span = span(10, 40);
        let operation_span = span(20, 21);
        let mut sink = RawSafetyFactSink::default();
        let group = sink.new_safety_scope(owner, scope_span);

        sink.record_operation(
            owner,
            operation_span,
            SafetyOpKind::DerefRawPointer,
            vec![scope_span, operation_span],
            Some(group),
        );
        sink.record_call(
            owner,
            Some(owner),
            Some(owner),
            span(30, 31),
            Some(group),
            false,
        );

        let facts = sink.into_facts();
        assert_eq!(facts.groups.len(), 1);
        assert_eq!(facts.groups[0].owner, owner);
        assert_eq!(facts.groups[0].effect_group.id, group.id);
        assert_eq!(facts.operations.len(), 1);
        assert_eq!(facts.operations[0].owner, owner);
        assert_eq!(facts.operations[0].op, SafetyOpKind::DerefRawPointer);
        assert_eq!(facts.operations[0].span, operation_span);
        assert_eq!(
            facts.operations[0].marker_anchor_spans,
            [scope_span, operation_span]
        );
        assert_eq!(facts.operations[0].effect_group.id, group.id);
        assert_eq!(facts.operations[0].effect_group.span, scope_span);
        assert_eq!(facts.calls.len(), 1);
        assert_eq!(facts.calls[0].owner, owner);
        assert_eq!(facts.calls[0].callee, Some(owner));
        assert_eq!(facts.calls[0].source_callee, Some(owner));
        assert_eq!(facts.calls[0].call_site, 0);
        assert_eq!(facts.calls[0].span, span(30, 31));
        assert_eq!(facts.calls[0].effect_group.id, group.id);
        assert_eq!(facts.calls[0].effect_group.span, scope_span);
    }

    #[test]
    fn raw_sink_coalesces_compiler_generated_calls_with_one_source_identity() {
        let owner = CRATE_DEF_ID.to_def_id();
        let generated_span = span(30, 31);
        let mut sink = RawSafetyFactSink::default();

        sink.record_call(owner, Some(owner), Some(owner), generated_span, None, false);
        sink.record_call(owner, Some(owner), Some(owner), generated_span, None, false);

        let facts = sink.into_facts();
        assert_eq!(facts.calls.len(), 1);
        assert_eq!(facts.calls[0].call_site, 0);
        assert_eq!(facts.calls[0].effect_group.id, 0);
    }

    #[test]
    fn raw_sink_keeps_same_source_call_in_distinct_unsafe_scopes() {
        let owner = CRATE_DEF_ID.to_def_id();
        let generated_span = span(30, 31);
        let mut sink = RawSafetyFactSink::default();
        let first_scope = sink.new_safety_scope(owner, span(10, 20));
        let second_scope = sink.new_safety_scope(owner, span(40, 50));

        sink.record_call(
            owner,
            Some(owner),
            Some(owner),
            generated_span,
            Some(first_scope),
            false,
        );
        sink.record_call(
            owner,
            Some(owner),
            Some(owner),
            generated_span,
            Some(second_scope),
            false,
        );

        let facts = sink.into_facts();
        assert_eq!(facts.calls.len(), 2);
        assert_eq!(facts.calls[0].effect_group, first_scope);
        assert_eq!(facts.calls[1].effect_group, second_scope);
    }

    #[test]
    fn raw_sink_retains_calls_inside_builtin_unsafe_blocks() {
        let owner = CRATE_DEF_ID.to_def_id();
        let generated_span = span(30, 31);
        let mut sink = RawSafetyFactSink::default();

        sink.record_call(owner, Some(owner), Some(owner), generated_span, None, true);

        let facts = sink.into_facts();
        assert_eq!(facts.calls.len(), 1);
        assert!(facts.calls[0].inside_builtin_unsafe);
    }

    #[test]
    fn raw_sink_retains_an_empty_unsafe_scope() {
        let owner = CRATE_DEF_ID.to_def_id();
        let scope_span = span(10, 40);
        let mut sink = RawSafetyFactSink::default();
        let group = sink.new_safety_scope(owner, scope_span);

        let facts = sink.into_facts();

        assert!(facts.calls.is_empty());
        assert!(facts.operations.is_empty());
        assert_eq!(facts.groups.len(), 1);
        assert_eq!(facts.groups[0].owner, owner);
        assert_eq!(facts.groups[0].effect_group.id, group.id);
        assert_eq!(facts.groups[0].effect_group.span, scope_span);
    }

    #[test]
    fn raw_sink_preserves_shared_and_standalone_effect_groups() {
        let owner = CRATE_DEF_ID.to_def_id();
        let scope_span = span(10, 40);
        let first_span = span(20, 21);
        let second_span = span(30, 31);
        let standalone_span = span(50, 51);
        let mut sink = RawSafetyFactSink::default();
        let shared_group = sink.new_safety_scope(owner, scope_span);

        for operation_span in [first_span, second_span] {
            sink.record_operation(
                owner,
                operation_span,
                SafetyOpKind::DerefRawPointer,
                vec![scope_span, operation_span],
                Some(shared_group),
            );
        }
        sink.record_operation(
            owner,
            standalone_span,
            SafetyOpKind::InlineAssembly,
            vec![standalone_span],
            None,
        );

        let facts = sink.into_facts().operations;
        assert_eq!(facts.len(), 3);
        assert_eq!(facts[0].effect_group.id, facts[1].effect_group.id);
        assert_eq!(facts[0].effect_group.span, scope_span);
        assert_ne!(facts[0].effect_group.id, facts[2].effect_group.id);
        assert_eq!(facts[2].effect_group.span, standalone_span);
    }
}
