//! MIR/HIR edge collection for one concrete function body.
//!
//! Most reachability facts come from MIR statements and terminators. A few
//! definitions, such as inline/anonymous const bodies, are easier to discover
//! from HIR, so this module scans both views before the graph builder turns
//! collected facts into graph nodes and edges.

use std::collections::HashMap;

use rustc_hir::{def_id::DefId, intravisit};
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
    CallableEdgeInfo, CompilerAssertLocal, CompilerAssertLocalRole, ReachabilityEdgeKind,
    ReachabilityNodeKind,
};

pub(crate) fn collect_body_edges<'tcx>(
    tcx: TyCtxt<'tcx>,
    caller: Instance<'tcx>,
) -> Vec<BodyEdge<'tcx>> {
    let body = tcx.instance_mir(caller.def);
    let mut visitor = BodyEdgeCollector {
        tcx,
        caller,
        body,
        edges: Vec::new(),
        callee_span: None,
    };

    visitor.visit_hir_definitions();
    rustc_middle::mir::visit::Visitor::visit_body(&mut visitor, body);
    visitor.edges
}

pub(crate) struct BodyEdge<'tcx> {
    pub target: ReachabilityNodeKind<'tcx>,
    pub kind: ReachabilityEdgeKind,
    pub span: Span,
    /// Callee-segment span for edges emitted while handling a call terminator.
    pub callee_span: Option<Span>,
    pub callable: Option<CallableEdgeInfo<'tcx>>,
}

struct BodyEdgeCollector<'tcx> {
    tcx: TyCtxt<'tcx>,
    caller: Instance<'tcx>,
    body: &'tcx Body<'tcx>,
    edges: Vec<BodyEdge<'tcx>>,
    /// Callee-segment span of the call terminator currently being handled.
    callee_span: Option<Span>,
}

impl<'tcx> BodyEdgeCollector<'tcx> {
    fn visit_hir_definitions(&mut self) {
        let Some(caller) = self.caller.def_id().as_local() else {
            return;
        };

        let Some(hir_body) = self.tcx.hir_maybe_body_owned_by(caller) else {
            return;
        };
        let mut visitor = HirDefinitionCollector { graph: self };
        intravisit::Visitor::visit_body(&mut visitor, hir_body);
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
        callable: Option<CallableEdgeInfo<'tcx>>,
    ) {
        self.edges.push(BodyEdge {
            target,
            kind,
            span,
            callee_span: self.callee_span,
            callable,
        });
    }

    fn emit_instance(&mut self, instance: Instance<'tcx>, kind: ReachabilityEdgeKind, span: Span) {
        self.emit_instance_with_callable(instance, kind, span, None);
    }

    fn emit_instance_with_callable(
        &mut self,
        instance: Instance<'tcx>,
        kind: ReachabilityEdgeKind,
        span: Span,
        callable: Option<CallableEdgeInfo<'tcx>>,
    ) {
        self.emit_edge(
            ReachabilityNodeKind::Instance(instance),
            kind,
            span,
            callable,
        );
    }

    fn emit_indirect_with_callable(
        &mut self,
        callee_ty: Ty<'tcx>,
        kind: ReachabilityEdgeKind,
        span: Span,
        callable: Option<CallableEdgeInfo<'tcx>>,
    ) {
        self.emit_edge(
            ReachabilityNodeKind::IndirectCall { callee_ty },
            kind,
            span,
            callable,
        );
    }

    fn emit_call_operand(&mut self, func: &Operand<'tcx>, kind: ReachabilityEdgeKind, span: Span) {
        let callee_ty = self.monomorphize(func.ty(&self.body.local_decls, self.tcx));
        let callable = self.callable_call_info(callee_ty);

        if let TyKind::FnDef(def_id, args) = *callee_ty.kind() {
            if let Some(instance) = self.resolve_callable_instance(def_id, args) {
                self.emit_instance_with_callable(instance, kind, span, callable);
            } else {
                self.emit_indirect_with_callable(
                    callee_ty,
                    ReachabilityEdgeKind::IndirectCall,
                    span,
                    callable,
                );
            }
        } else {
            self.emit_indirect_with_callable(
                callee_ty,
                ReachabilityEdgeKind::IndirectCall,
                span,
                callable,
            );
        }
    }

    fn emit_callable_ty(
        &mut self,
        ty: Ty<'tcx>,
        fn_ptr_ty: Option<Ty<'tcx>>,
        kind: ReachabilityEdgeKind,
        span: Span,
    ) {
        let callable = fn_ptr_ty.map(|fn_ptr_ty| CallableEdgeInfo::FnPointer { fn_ptr_ty });
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
                    self.emit_instance_with_callable(instance, kind, span, callable);
                } else {
                    self.emit_indirect_with_callable(ty, kind, span, callable);
                }
            }
            TyKind::Closure(def_id, args) => {
                let instance =
                    Instance::resolve_closure(self.tcx, *def_id, args, ty::ClosureKind::FnOnce);
                self.emit_instance_with_callable(instance, kind, span, callable);
            }
            _ => {}
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

    fn emit_assert(&mut self, message: Box<AssertMessage<'tcx>>, span: Span) {
        self.emit_edge(
            ReachabilityNodeKind::CompilerAssert {
                message,
                locals: self.compiler_assert_locals(),
            },
            ReachabilityEdgeKind::Assert,
            span,
            None,
        );
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

    fn visit_assignment(&mut self, rvalue: &Rvalue<'tcx>, span: Span) {
        match rvalue {
            Rvalue::Cast(
                CastKind::PointerCoercion(PointerCoercion::ReifyFnPointer(_), _),
                operand,
                target_ty,
            ) => {
                let ty = self.monomorphize(operand.ty(&self.body.local_decls, self.tcx));
                let target_ty = self.monomorphize(*target_ty);
                self.emit_callable_ty(
                    ty,
                    Some(target_ty),
                    ReachabilityEdgeKind::FnPointerReify,
                    span,
                );
            }
            Rvalue::Cast(
                CastKind::PointerCoercion(PointerCoercion::ClosureFnPointer(_), _),
                operand,
                target_ty,
            ) => {
                let ty = self.monomorphize(operand.ty(&self.body.local_decls, self.tcx));
                let target_ty = self.monomorphize(*target_ty);
                self.emit_callable_ty(
                    ty,
                    Some(target_ty),
                    ReachabilityEdgeKind::ClosureFnPointerReify,
                    span,
                );
            }
            Rvalue::Cast(
                CastKind::PointerCoercion(PointerCoercion::Unsize, _),
                operand,
                target_ty,
            ) => {
                let source_ty = self.monomorphize(operand.ty(&self.body.local_decls, self.tcx));
                let target_ty = self.monomorphize(*target_ty);
                self.emit_dyn_object_cast(source_ty, target_ty, span);
                self.emit_vtable_entries(source_ty, target_ty, span);
            }
            // A coroutine aggregate stores the runtime body that may execute
            // when the value is polled. This is deliberately structural:
            // construction makes that body reachable even if local dataflow
            // could prove a particular value is never polled. In contrast, a
            // CoroutineClosure aggregate only creates a callable; its actual
            // invocation reaches the returned Coroutine through its call shim.
            Rvalue::Aggregate(kind, _) if matches!(kind.as_ref(), AggregateKind::Coroutine(..)) => {
                let AggregateKind::Coroutine(def_id, args) = kind.as_ref() else {
                    unreachable!("guarded by the coroutine aggregate match")
                };
                let args = self.monomorphize(*args);
                self.emit_instance(
                    Instance::new_raw(*def_id, args),
                    ReachabilityEdgeKind::CoroutineBody,
                    span,
                );
            }
            _ => {}
        }
    }

    fn emit_dyn_object_cast(&mut self, source_ty: Ty<'tcx>, target_ty: Ty<'tcx>, span: Span) {
        self.emit_edge(
            ReachabilityNodeKind::DynObjectCast {
                source_ty,
                target_ty,
            },
            ReachabilityEdgeKind::DynObjectCast,
            span,
            None,
        );
    }

    fn callable_call_info(&self, callee_ty: Ty<'tcx>) -> Option<CallableEdgeInfo<'tcx>> {
        match *callee_ty.kind() {
            TyKind::FnPtr(..) => Some(CallableEdgeInfo::FnPointer {
                fn_ptr_ty: callee_ty,
            }),
            TyKind::FnDef(def_id, args) => {
                let trait_def_id = self.tcx.trait_of_assoc(def_id)?;
                let self_ty = self_arg_ty(args)?;
                if matches!(self_ty.kind(), TyKind::FnPtr(..)) {
                    Some(CallableEdgeInfo::FnPointer { fn_ptr_ty: self_ty })
                } else if ty_contains_dyn(self_ty) {
                    Some(CallableEdgeInfo::DynDispatch { trait_def_id })
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn emit_vtable_entries(&mut self, source_ty: Ty<'tcx>, target_ty: Ty<'tcx>, span: Span) {
        let tcx = self.tcx;
        for_each_dyn_vtable_method(tcx, source_ty, target_ty, |trait_def_id, instance| {
            self.emit_instance_with_callable(
                instance,
                ReachabilityEdgeKind::VTableEntry,
                span,
                Some(CallableEdgeInfo::DynDispatch { trait_def_id }),
            );
        });
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

fn self_arg_ty(args: GenericArgsRef<'_>) -> Option<Ty<'_>> {
    args.iter().next().and_then(|arg| {
        if let ty::GenericArgKind::Type(ty) = arg.kind() {
            Some(ty)
        } else {
            None
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

/// Visits the resolved vtable methods a `source_ty` to `target_ty` unsizing
/// introduces, with the principal trait's def id. This single pipeline backs
/// both dyn-dispatch attribution modes, so cast-site and call-site edges
/// cannot drift apart.
fn for_each_dyn_vtable_method<'tcx>(
    tcx: TyCtxt<'tcx>,
    source_ty: Ty<'tcx>,
    target_ty: Ty<'tcx>,
    mut visit: impl FnMut(DefId, Instance<'tcx>),
) {
    for (impl_ty, trait_ty) in dyn_trait_tails(source_ty, target_ty) {
        let TyKind::Dynamic(predicates, _) = trait_ty.kind() else {
            continue;
        };
        let Some(principal) = predicates.principal() else {
            continue;
        };

        let trait_def_id = principal.def_id();
        let trait_ref =
            tcx.instantiate_bound_regions_with_erased(principal.with_self_ty(tcx, impl_ty));
        if trait_ref.has_param() {
            continue;
        }

        for entry in tcx.vtable_entries(trait_ref) {
            if let VtblEntry::Method(instance) = entry {
                visit(trait_def_id, *instance);
            }
        }
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

struct HirDefinitionCollector<'a, 'tcx> {
    graph: &'a mut BodyEdgeCollector<'tcx>,
}

impl<'tcx> HirDefinitionCollector<'_, 'tcx> {
    fn const_body_args(&self, def_id: rustc_hir::def_id::DefId) -> GenericArgsRef<'tcx> {
        let args = GenericArgs::identity_for_item(self.graph.tcx, def_id);
        if args.len() <= self.graph.caller.args.len() {
            self.graph.monomorphize(args)
        } else {
            args
        }
    }
}

impl<'tcx> intravisit::Visitor<'tcx> for HirDefinitionCollector<'_, 'tcx> {
    type NestedFilter = nested_filter::OnlyBodies;
    type MaybeTyCtxt = TyCtxt<'tcx>;

    fn maybe_tcx(&mut self) -> Self::MaybeTyCtxt {
        self.graph.tcx
    }

    fn visit_anon_const(&mut self, c: &'tcx rustc_hir::AnonConst) -> Self::Result {
        let def_id = c.def_id.to_def_id();
        let args = self.const_body_args(def_id);
        let instance = Instance::new_raw(def_id, args);
        self.graph
            .emit_instance(instance, ReachabilityEdgeKind::ConstBody, c.span);
    }

    fn visit_inline_const(&mut self, c: &'tcx rustc_hir::ConstBlock) -> Self::Result {
        let def_id = c.def_id.to_def_id();
        let args = self.const_body_args(def_id);
        let span = self.graph.tcx.hir_body(c.body).value.span;
        let instance = Instance::new_raw(def_id, args);
        self.graph
            .emit_instance(instance, ReachabilityEdgeKind::ConstBody, span);
    }
}

impl<'tcx> rustc_middle::mir::visit::Visitor<'tcx> for BodyEdgeCollector<'tcx> {
    fn visit_statement(
        &mut self,
        statement: &rustc_middle::mir::Statement<'tcx>,
        location: rustc_middle::mir::Location,
    ) {
        if let StatementKind::Assign(assignment) = &statement.kind {
            let (_, rvalue) = &**assignment;
            self.visit_assignment(rvalue, statement.source_info.span);
        }

        self.super_statement(statement, location);
    }

    fn visit_terminator(
        &mut self,
        terminator: &rustc_middle::mir::Terminator<'tcx>,
        location: rustc_middle::mir::Location,
    ) {
        match &terminator.kind {
            TerminatorKind::Call { func, fn_span, .. } => {
                self.callee_span = Some(*fn_span);
                self.emit_call_operand(
                    func,
                    ReachabilityEdgeKind::DirectCall,
                    terminator.source_info.span,
                );
                self.callee_span = None;
            }
            TerminatorKind::TailCall { func, fn_span, .. } => {
                self.callee_span = Some(*fn_span);
                self.emit_call_operand(
                    func,
                    ReachabilityEdgeKind::TailCall,
                    terminator.source_info.span,
                );
                self.callee_span = None;
            }
            TerminatorKind::Assert { msg, .. } => {
                self.emit_assert(msg.clone(), terminator.source_info.span);
            }
            _ => {}
        }

        self.super_terminator(terminator, location);
    }
}
