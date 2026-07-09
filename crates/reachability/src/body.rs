//! MIR/HIR edge collection for one concrete function body.
//!
//! Most reachability facts come from MIR statements and terminators. A few
//! definitions, such as closure expressions and inline/anonymous const bodies,
//! are easier to discover from HIR, so this module scans both views before the
//! graph builder turns collected facts into graph nodes and edges.

use std::collections::HashMap;
use std::ops::ControlFlow;

use rustc_hir::{
    ExprKind,
    def_id::{DefId, LocalDefId},
    intravisit,
};
use rustc_middle::hir::nested_filter;
use rustc_middle::mir::AssertMessage;
use rustc_middle::mir::{
    AggregateKind, Body, CastKind, LocalKind, Operand, Rvalue, StatementKind, TerminatorKind,
    VarDebugInfoContents,
};
use rustc_middle::ty::adjustment::PointerCoercion;
use rustc_middle::ty::vtable::VtblEntry;
use rustc_middle::ty::{
    self, EarlyBinder, GenericArgs, GenericArgsRef, Instance, Ty, TyCtxt, TyKind, TypeFoldable,
    TypeVisitableExt,
};
use rustc_span::Span;

use crate::graph::{
    CompilerAssertLocal, CompilerAssertLocalRole, ReachabilityEdgeKind, ReachabilityNodeKind,
};
use crate::hooks::{ReachabilityControl, ReachabilityHalt};

pub(crate) fn collect_body_edges<'tcx>(
    tcx: TyCtxt<'tcx>,
    caller: Instance<'tcx>,
    mut emit: impl FnMut(BodyEdge<'tcx>) -> ReachabilityControl<'tcx>,
) -> ReachabilityControl<'tcx> {
    let body = tcx.instance_mir(caller.def);
    let mut visitor = BodyEdgeCollector {
        tcx,
        caller,
        body,
        emit: &mut emit,
        halt: None,
        dyn_vtable_entries: Vec::new(),
        callee_span: None,
    };

    visitor.collect_dyn_vtable_entries();
    visitor.visit_hir_definitions()?;
    rustc_middle::mir::visit::Visitor::visit_body(&mut visitor, body);

    if let Some(halt) = visitor.take_halt() {
        ControlFlow::Break(halt)
    } else {
        ControlFlow::Continue(())
    }
}

pub(crate) struct BodyEdge<'tcx> {
    pub target: ReachabilityNodeKind<'tcx>,
    pub kind: ReachabilityEdgeKind,
    pub span: Span,
    /// Callee-segment span for edges emitted while handling a call terminator.
    pub callee_span: Option<Span>,
}

struct BodyEdgeCollector<'a, 'tcx, F>
where
    F: FnMut(BodyEdge<'tcx>) -> ReachabilityControl<'tcx>,
{
    tcx: TyCtxt<'tcx>,
    caller: Instance<'tcx>,
    body: &'tcx Body<'tcx>,
    emit: &'a mut F,
    halt: Option<ReachabilityHalt<'tcx>>,
    dyn_vtable_entries: Vec<DynVTableEntry<'tcx>>,
    /// Callee-segment span of the call terminator currently being handled.
    callee_span: Option<Span>,
}

#[derive(Clone, Copy)]
struct DynVTableEntry<'tcx> {
    trait_def_id: DefId,
    instance: Instance<'tcx>,
}

impl<'tcx, F> BodyEdgeCollector<'_, 'tcx, F>
where
    F: FnMut(BodyEdge<'tcx>) -> ReachabilityControl<'tcx>,
{
    fn visit_hir_definitions(&mut self) -> ReachabilityControl<'tcx> {
        let Some(caller) = self.caller.def_id().as_local() else {
            return ControlFlow::Continue(());
        };

        let Some(hir_body) = self.tcx.hir_maybe_body_owned_by(caller) else {
            return ControlFlow::Continue(());
        };
        let mut visitor = HirDefinitionCollector {
            graph: self,
            caller,
        };
        intravisit::Visitor::visit_body(&mut visitor, hir_body);

        if let Some(halt) = visitor.take_halt() {
            ControlFlow::Break(halt)
        } else {
            ControlFlow::Continue(())
        }
    }

    fn monomorphize<T>(&self, value: T) -> T
    where
        T: TypeFoldable<TyCtxt<'tcx>>,
    {
        let value = EarlyBinder::bind(value);
        if self.caller.args.has_param() {
            value
                .instantiate(self.tcx, self.caller.args)
                .skip_norm_wip()
        } else {
            self.caller.instantiate_mir_and_normalize_erasing_regions(
                self.tcx,
                ty::TypingEnv::fully_monomorphized(),
                value,
            )
        }
    }

    fn emit_edge(
        &mut self,
        target: ReachabilityNodeKind<'tcx>,
        kind: ReachabilityEdgeKind,
        span: Span,
    ) -> ReachabilityControl<'tcx> {
        if let Some(halt) = &self.halt {
            return ControlFlow::Break(halt.clone());
        }

        let edge = BodyEdge {
            target,
            kind,
            span,
            callee_span: self.callee_span,
        };

        match (self.emit)(edge) {
            ControlFlow::Continue(()) => ControlFlow::Continue(()),
            ControlFlow::Break(halt) => {
                self.halt = Some(halt.clone());
                ControlFlow::Break(halt)
            }
        }
    }

    fn emit_instance(
        &mut self,
        instance: Instance<'tcx>,
        kind: ReachabilityEdgeKind,
        span: Span,
    ) -> ReachabilityControl<'tcx> {
        self.emit_edge(ReachabilityNodeKind::Instance(instance), kind, span)
    }

    fn emit_indirect(
        &mut self,
        callee_ty: Ty<'tcx>,
        kind: ReachabilityEdgeKind,
        span: Span,
    ) -> ReachabilityControl<'tcx> {
        self.emit_edge(ReachabilityNodeKind::IndirectCall { callee_ty }, kind, span)
    }

    fn emit_call_operand(
        &mut self,
        func: &Operand<'tcx>,
        kind: ReachabilityEdgeKind,
        span: Span,
    ) -> ReachabilityControl<'tcx> {
        let callee_ty = self.monomorphize(func.ty(&self.body.local_decls, self.tcx));
        let dyn_dispatch_trait = self.dyn_dispatch_trait(callee_ty);

        if let TyKind::FnDef(def_id, args) = *callee_ty.kind() {
            if let Some(instance) = self.resolve_callable_instance(def_id, args) {
                self.emit_instance(instance, kind, span)?;
            } else {
                self.emit_indirect(callee_ty, ReachabilityEdgeKind::IndirectCall, span)?;
            }
        } else {
            self.emit_indirect(callee_ty, ReachabilityEdgeKind::IndirectCall, span)?;
        }

        if let Some(trait_def_id) = dyn_dispatch_trait {
            self.emit_dyn_dispatch_vtable_entries(trait_def_id, span)?;
        }

        ControlFlow::Continue(())
    }

    fn emit_callable_ty(
        &mut self,
        ty: Ty<'tcx>,
        kind: ReachabilityEdgeKind,
        span: Span,
    ) -> ReachabilityControl<'tcx> {
        match ty.kind() {
            TyKind::FnDef(def_id, args) => {
                let instance = match kind {
                    ReachabilityEdgeKind::FnPointerReify => {
                        if args.has_param() {
                            self.resolve_callable_instance(*def_id, args)
                        } else {
                            Instance::resolve_for_fn_ptr(
                                self.tcx,
                                ty::TypingEnv::fully_monomorphized(),
                                *def_id,
                                args,
                            )
                        }
                    }
                    _ => self.resolve_callable_instance(*def_id, args),
                };
                if let Some(instance) = instance {
                    self.emit_instance(instance, kind, span)
                } else {
                    self.emit_indirect(ty, kind, span)
                }
            }
            TyKind::Closure(def_id, args) => {
                let instance =
                    Instance::resolve_closure(self.tcx, *def_id, args, ty::ClosureKind::FnOnce);
                self.emit_instance(instance, kind, span)
            }
            _ => ControlFlow::Continue(()),
        }
    }

    fn resolve_callable_instance(
        &self,
        def_id: rustc_hir::def_id::DefId,
        args: GenericArgsRef<'tcx>,
    ) -> Option<Instance<'tcx>> {
        if args.has_param() {
            if self.tcx.trait_of_assoc(def_id).is_some() {
                None
            } else {
                Some(Instance::new_raw(def_id, args))
            }
        } else {
            Instance::try_resolve(self.tcx, ty::TypingEnv::fully_monomorphized(), def_id, args)
                .ok()
                .flatten()
        }
    }

    fn emit_assert(
        &mut self,
        message: Box<AssertMessage<'tcx>>,
        span: Span,
    ) -> ReachabilityControl<'tcx> {
        self.emit_edge(
            ReachabilityNodeKind::CompilerAssert {
                message,
                locals: self.compiler_assert_locals(),
            },
            ReachabilityEdgeKind::Assert,
            span,
        )
    }

    fn compiler_assert_locals(&self) -> Vec<CompilerAssertLocal> {
        let mut source_names = HashMap::<usize, String>::new();
        for debug_info in &self.body.var_debug_info {
            let VarDebugInfoContents::Place(place) = debug_info.value else {
                continue;
            };
            if !place.projection.is_empty() {
                continue;
            }
            source_names
                .entry(place.local.index())
                .or_insert_with(|| debug_info.name.to_string());
        }

        self.body
            .local_decls
            .iter_enumerated()
            .map(|(local, _)| CompilerAssertLocal {
                index: local.index(),
                name: source_names
                    .remove(&local.index())
                    .filter(|name| !name.is_empty()),
                role: match self.body.local_kind(local) {
                    LocalKind::ReturnPointer => CompilerAssertLocalRole::ReturnPointer,
                    LocalKind::Arg => CompilerAssertLocalRole::Argument,
                    LocalKind::Temp => CompilerAssertLocalRole::Temporary,
                },
            })
            .collect()
    }

    fn visit_assignment(&mut self, rvalue: &Rvalue<'tcx>, span: Span) -> ReachabilityControl<'tcx> {
        match rvalue {
            Rvalue::Cast(
                CastKind::PointerCoercion(PointerCoercion::ReifyFnPointer(_), _),
                operand,
                _,
            ) => {
                let ty = self.monomorphize(operand.ty(&self.body.local_decls, self.tcx));
                self.emit_callable_ty(ty, ReachabilityEdgeKind::FnPointerReify, span)
            }
            Rvalue::Cast(
                CastKind::PointerCoercion(PointerCoercion::ClosureFnPointer(_), _),
                operand,
                _,
            ) => {
                let ty = self.monomorphize(operand.ty(&self.body.local_decls, self.tcx));
                self.emit_callable_ty(ty, ReachabilityEdgeKind::ClosureFnPointerReify, span)
            }
            Rvalue::Cast(
                CastKind::PointerCoercion(PointerCoercion::Unsize, _),
                operand,
                target_ty,
            ) => {
                let source_ty = self.monomorphize(operand.ty(&self.body.local_decls, self.tcx));
                let target_ty = self.monomorphize(*target_ty);
                self.emit_dyn_object_cast(source_ty, target_ty, span)?;
                self.emit_vtable_entries(source_ty, target_ty, span)
            }
            Rvalue::Aggregate(kind, _) => {
                if let AggregateKind::Closure(def_id, args) = **kind {
                    let args = self.monomorphize(args);
                    let instance =
                        Instance::resolve_closure(self.tcx, def_id, args, ty::ClosureKind::FnOnce);
                    self.emit_instance(instance, ReachabilityEdgeKind::ClosureDefinition, span)
                } else {
                    ControlFlow::Continue(())
                }
            }
            _ => ControlFlow::Continue(()),
        }
    }

    fn emit_dyn_object_cast(
        &mut self,
        source_ty: Ty<'tcx>,
        target_ty: Ty<'tcx>,
        span: Span,
    ) -> ReachabilityControl<'tcx> {
        self.emit_edge(
            ReachabilityNodeKind::DynObjectCast {
                source_ty,
                target_ty,
            },
            ReachabilityEdgeKind::DynObjectCast,
            span,
        )
    }

    fn collect_dyn_vtable_entries(&mut self) {
        let mut dyn_object_casts = Vec::new();

        for block in self.body.basic_blocks.iter() {
            for statement in &block.statements {
                if let StatementKind::Assign(assignment) = &statement.kind {
                    let (_, rvalue) = &**assignment;
                    if let Some(cast) = self.dyn_object_cast_types(rvalue) {
                        dyn_object_casts.push(cast);
                    }
                }
            }
        }

        for (source_ty, target_ty) in dyn_object_casts {
            self.record_dyn_vtable_entries(source_ty, target_ty);
        }
    }

    fn dyn_object_cast_types(&self, rvalue: &Rvalue<'tcx>) -> Option<(Ty<'tcx>, Ty<'tcx>)> {
        if let Rvalue::Cast(
            CastKind::PointerCoercion(PointerCoercion::Unsize, _),
            operand,
            target_ty,
        ) = rvalue
        {
            let source_ty = self.monomorphize(operand.ty(&self.body.local_decls, self.tcx));
            let target_ty = self.monomorphize(*target_ty);
            Some((source_ty, target_ty))
        } else {
            None
        }
    }

    fn record_dyn_vtable_entries(&mut self, source_ty: Ty<'tcx>, target_ty: Ty<'tcx>) {
        for (impl_ty, trait_ty) in dyn_trait_tails(source_ty, target_ty) {
            let TyKind::Dynamic(predicates, _) = trait_ty.kind() else {
                continue;
            };
            let Some(principal) = predicates.principal() else {
                continue;
            };

            let trait_def_id = principal.def_id();
            let trait_ref = self
                .tcx
                .instantiate_bound_regions_with_erased(principal.with_self_ty(self.tcx, impl_ty));
            if trait_ref.has_param() {
                continue;
            }

            for entry in self.tcx.vtable_entries(trait_ref) {
                if let VtblEntry::Method(instance) = entry {
                    self.record_dyn_vtable_entry(trait_def_id, *instance);
                }
            }
        }
    }

    fn record_dyn_vtable_entry(&mut self, trait_def_id: DefId, instance: Instance<'tcx>) {
        if !self
            .dyn_vtable_entries
            .iter()
            .any(|entry| entry.trait_def_id == trait_def_id && entry.instance == instance)
        {
            self.dyn_vtable_entries.push(DynVTableEntry {
                trait_def_id,
                instance,
            });
        }
    }

    fn emit_dyn_dispatch_vtable_entries(
        &mut self,
        trait_def_id: DefId,
        span: Span,
    ) -> ReachabilityControl<'tcx> {
        for index in 0..self.dyn_vtable_entries.len() {
            let entry = self.dyn_vtable_entries[index];
            if entry.trait_def_id != trait_def_id {
                continue;
            }
            self.emit_instance(
                entry.instance,
                ReachabilityEdgeKind::DynDispatchVTableEntry,
                span,
            )?;
        }

        ControlFlow::Continue(())
    }

    fn dyn_dispatch_trait(&self, callee_ty: Ty<'tcx>) -> Option<DefId> {
        if self.dyn_vtable_entries.is_empty() {
            return None;
        }

        let TyKind::FnDef(def_id, args) = *callee_ty.kind() else {
            return None;
        };

        if self_arg_contains_dyn(args) {
            self.tcx.trait_of_assoc(def_id)
        } else {
            None
        }
    }

    fn emit_vtable_entries(
        &mut self,
        source_ty: Ty<'tcx>,
        target_ty: Ty<'tcx>,
        span: Span,
    ) -> ReachabilityControl<'tcx> {
        for (impl_ty, trait_ty) in dyn_trait_tails(source_ty, target_ty) {
            let TyKind::Dynamic(predicates, _) = trait_ty.kind() else {
                continue;
            };
            let Some(principal) = predicates.principal() else {
                continue;
            };

            let trait_ref = self
                .tcx
                .instantiate_bound_regions_with_erased(principal.with_self_ty(self.tcx, impl_ty));
            if trait_ref.has_param() {
                continue;
            }

            for entry in self.tcx.vtable_entries(trait_ref) {
                if let VtblEntry::Method(instance) = entry {
                    self.emit_instance(*instance, ReachabilityEdgeKind::VTableEntry, span)?;
                }
            }
        }

        ControlFlow::Continue(())
    }

    fn take_halt(&mut self) -> Option<ReachabilityHalt<'tcx>> {
        self.halt.take()
    }
}

fn generic_args_contain_dyn(args: GenericArgsRef<'_>) -> bool {
    args.iter().any(|arg| {
        if let ty::GenericArgKind::Type(ty) = arg.kind() {
            ty_contains_dyn(ty)
        } else {
            false
        }
    })
}

fn self_arg_contains_dyn(args: GenericArgsRef<'_>) -> bool {
    args.iter().next().is_some_and(|arg| {
        if let ty::GenericArgKind::Type(ty) = arg.kind() {
            ty_contains_dyn(ty)
        } else {
            false
        }
    })
}

fn ty_contains_dyn(ty: Ty<'_>) -> bool {
    match ty.kind() {
        TyKind::Dynamic(..) => true,
        TyKind::Ref(_, inner, _)
        | TyKind::RawPtr(inner, _)
        | TyKind::Array(inner, _)
        | TyKind::Slice(inner) => ty_contains_dyn(*inner),
        TyKind::Tuple(types) => types.iter().any(ty_contains_dyn),
        TyKind::Adt(_, args)
        | TyKind::FnDef(_, args)
        | TyKind::Closure(_, args)
        | TyKind::CoroutineClosure(_, args)
        | TyKind::Coroutine(_, args)
        | TyKind::CoroutineWitness(_, args)
        | TyKind::Alias(ty::AliasTy { args, .. }) => generic_args_contain_dyn(args),
        _ => false,
    }
}

fn dyn_trait_tails<'tcx>(source_ty: Ty<'tcx>, target_ty: Ty<'tcx>) -> Vec<(Ty<'tcx>, Ty<'tcx>)> {
    let mut tails = Vec::new();
    collect_dyn_trait_tails(source_ty, target_ty, &mut tails);
    tails
}

fn collect_dyn_trait_tails<'tcx>(
    source_ty: Ty<'tcx>,
    target_ty: Ty<'tcx>,
    tails: &mut Vec<(Ty<'tcx>, Ty<'tcx>)>,
) {
    match (source_ty.kind(), target_ty.kind()) {
        (_, TyKind::Dynamic(..)) if !source_ty.is_trait() => tails.push((source_ty, target_ty)),
        (TyKind::Ref(_, source_inner, _), TyKind::Ref(_, target_inner, _))
        | (TyKind::RawPtr(source_inner, _), TyKind::RawPtr(target_inner, _)) => {
            collect_dyn_trait_tails(*source_inner, *target_inner, tails);
        }
        (TyKind::Adt(source_def, source_args), TyKind::Adt(target_def, target_args))
            if source_def.did() == target_def.did() =>
        {
            for (source_arg, target_arg) in source_args.iter().zip(target_args.iter()) {
                if let (ty::GenericArgKind::Type(source_ty), ty::GenericArgKind::Type(target_ty)) =
                    (source_arg.kind(), target_arg.kind())
                {
                    collect_dyn_trait_tails(source_ty, target_ty, tails);
                }
            }
        }
        (TyKind::Tuple(source_tys), TyKind::Tuple(target_tys))
            if source_tys.len() == target_tys.len() =>
        {
            for (source_ty, target_ty) in source_tys.iter().zip(target_tys.iter()) {
                collect_dyn_trait_tails(source_ty, target_ty, tails);
            }
        }
        _ => {}
    }
}

struct HirDefinitionCollector<'a, 'b, 'tcx, F>
where
    F: FnMut(BodyEdge<'tcx>) -> ReachabilityControl<'tcx>,
{
    graph: &'a mut BodyEdgeCollector<'b, 'tcx, F>,
    caller: LocalDefId,
}

impl<'tcx, F> HirDefinitionCollector<'_, '_, 'tcx, F>
where
    F: FnMut(BodyEdge<'tcx>) -> ReachabilityControl<'tcx>,
{
    fn take_halt(&mut self) -> Option<ReachabilityHalt<'tcx>> {
        self.graph.take_halt()
    }

    fn const_body_args(&self, def_id: rustc_hir::def_id::DefId) -> GenericArgsRef<'tcx> {
        let args = GenericArgs::identity_for_item(self.graph.tcx, def_id);
        if args.len() <= self.graph.caller.args.len() {
            self.graph.monomorphize(args)
        } else {
            args
        }
    }
}

impl<'tcx, F> intravisit::Visitor<'tcx> for HirDefinitionCollector<'_, '_, 'tcx, F>
where
    F: FnMut(BodyEdge<'tcx>) -> ReachabilityControl<'tcx>,
{
    type NestedFilter = nested_filter::OnlyBodies;
    type MaybeTyCtxt = TyCtxt<'tcx>;

    fn maybe_tcx(&mut self) -> Self::MaybeTyCtxt {
        self.graph.tcx
    }

    fn visit_expr(&mut self, expr: &'tcx rustc_hir::Expr<'tcx>) -> Self::Result {
        if self.graph.halt.is_some() {
            return;
        }

        if let ExprKind::Closure(_) = expr.kind {
            let ty = self.graph.tcx.typeck(self.caller).expr_ty(expr);
            let ty = self.graph.monomorphize(ty);
            let _ =
                self.graph
                    .emit_callable_ty(ty, ReachabilityEdgeKind::ClosureDefinition, expr.span);
            return;
        }

        intravisit::walk_expr(self, expr);
    }

    fn visit_anon_const(&mut self, c: &'tcx rustc_hir::AnonConst) -> Self::Result {
        if self.graph.halt.is_some() {
            return;
        }

        let def_id = c.def_id.to_def_id();
        let args = self.const_body_args(def_id);
        let instance = Instance::new_raw(def_id, args);
        let _ = self
            .graph
            .emit_instance(instance, ReachabilityEdgeKind::ConstBody, c.span);
    }

    fn visit_inline_const(&mut self, c: &'tcx rustc_hir::ConstBlock) -> Self::Result {
        if self.graph.halt.is_some() {
            return;
        }

        let def_id = c.def_id.to_def_id();
        let args = self.const_body_args(def_id);
        let span = self.graph.tcx.hir_body(c.body).value.span;
        let instance = Instance::new_raw(def_id, args);
        let _ = self
            .graph
            .emit_instance(instance, ReachabilityEdgeKind::ConstBody, span);
    }
}

impl<'tcx, F> rustc_middle::mir::visit::Visitor<'tcx> for BodyEdgeCollector<'_, 'tcx, F>
where
    F: FnMut(BodyEdge<'tcx>) -> ReachabilityControl<'tcx>,
{
    fn visit_statement(
        &mut self,
        statement: &rustc_middle::mir::Statement<'tcx>,
        location: rustc_middle::mir::Location,
    ) {
        if self.halt.is_some() {
            return;
        }

        if let StatementKind::Assign(assignment) = &statement.kind {
            let (_, rvalue) = &**assignment;
            let _ = self.visit_assignment(rvalue, statement.source_info.span);
        }

        self.super_statement(statement, location);
    }

    fn visit_terminator(
        &mut self,
        terminator: &rustc_middle::mir::Terminator<'tcx>,
        location: rustc_middle::mir::Location,
    ) {
        if self.halt.is_some() {
            return;
        }

        match &terminator.kind {
            TerminatorKind::Call { func, fn_span, .. } => {
                self.callee_span = Some(*fn_span);
                let _ = self.emit_call_operand(
                    func,
                    ReachabilityEdgeKind::DirectCall,
                    terminator.source_info.span,
                );
                self.callee_span = None;
            }
            TerminatorKind::TailCall { func, fn_span, .. } => {
                self.callee_span = Some(*fn_span);
                let _ = self.emit_call_operand(
                    func,
                    ReachabilityEdgeKind::TailCall,
                    terminator.source_info.span,
                );
                self.callee_span = None;
            }
            TerminatorKind::Assert { msg, .. } => {
                let _ = self.emit_assert(msg.clone(), terminator.source_info.span);
            }
            _ => {}
        }

        self.super_terminator(terminator, location);
    }
}
