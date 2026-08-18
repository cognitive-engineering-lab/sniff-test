//! Deterministic scheduling and isolated output for artifact collection passes.
//!
//! A pass declares every fact-table schema that it reads and writes. The
//! scheduler uses those declarations as the dependency graph, orders otherwise
//! independent passes by [`PassId`], and rejects ambiguous graphs before any
//! compiler query or database mutation occurs. A running pass writes only to an
//! isolated [`ArtifactDbBuilder`] delta; callers receive that delta only after
//! the pass returns successfully.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use super::builder::{
    ArtifactDbBuilder, ArtifactDbDraftView, BuildError, DraftFact, DraftRelation, FactMeta,
};
use super::registry::{SchemaRegistry, SchemaRegistryError};
use super::schema::{
    EntityHandle, EntitySchema, FactSchema, PassId, RelationSchema, RequirementSchema, RowHandle,
    RowSchema, SchemaId,
};

/// Static dependency declaration for one artifact pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PassDescriptor {
    pub(crate) id: PassId,
    pub(crate) reads: Vec<SchemaId>,
    pub(crate) writes: Vec<SchemaId>,
}

impl PassDescriptor {
    pub(crate) fn new(id: PassId) -> Self {
        Self {
            id,
            reads: Vec::new(),
            writes: Vec::new(),
        }
    }

    pub(crate) fn with_reads(mut self, reads: impl IntoIterator<Item = SchemaId>) -> Self {
        self.reads.extend(reads);
        self
    }

    pub(crate) fn with_writes(mut self, writes: impl IntoIterator<Item = SchemaId>) -> Self {
        self.writes.extend(writes);
        self
    }
}

/// A compiler-aware, policy-neutral artifact collection pass.
///
/// The compiler context type is chosen by the composition root. The trait is
/// object-safe so packs can register heterogeneous pass implementations without
/// a dynamic-plugin ABI or an `Any` typemap.
pub(crate) trait ArtifactPass<C: ?Sized> {
    fn descriptor(&self) -> PassDescriptor;

    fn run(
        &mut self,
        cx: &C,
        input: PassInput<'_>,
        output: &mut PassOutput<'_>,
    ) -> Result<(), PassError>;
}

/// Registry-backed, declaration-guarded view exposed to one artifact pass.
///
/// The raw draft database is deliberately hidden. Every typed read proves
/// both that the Rust schema owns its registered stable ID and that the pass
/// declared the schema as an input, preserving the scheduler's dependency
/// graph as an executable contract.
#[derive(Clone, Copy)]
pub(crate) struct PassInput<'a> {
    pass: &'a PassId,
    declared_reads: &'a BTreeSet<SchemaId>,
    registry: &'a SchemaRegistry,
    view: ArtifactDbDraftView<'a>,
}

impl<'a> PassInput<'a> {
    fn new(
        pass: &'a PassId,
        declared_reads: &'a BTreeSet<SchemaId>,
        registry: &'a SchemaRegistry,
        view: ArtifactDbDraftView<'a>,
    ) -> Self {
        Self {
            pass,
            declared_reads,
            registry,
            view,
        }
    }

    pub(crate) fn table<S: RowSchema>(self) -> Result<Vec<S>, PassError> {
        let schema = self.authorize::<S>()?;
        self.view.table::<S>().map_err(|source| PassError::Build {
            pass: self.pass.clone(),
            schema,
            source: Box::new(source),
        })
    }

    pub(crate) fn contains_schema<S: RowSchema>(self) -> Result<bool, PassError> {
        self.authorize::<S>()?;
        Ok(self.view.contains_schema::<S>())
    }

    pub(crate) fn facts<F: FactSchema>(self) -> Result<Vec<DraftFact<F>>, PassError> {
        let schema = self.authorize::<F>()?;
        self.view.facts::<F>().map_err(|source| PassError::Build {
            pass: self.pass.clone(),
            schema,
            source: Box::new(source),
        })
    }

    pub(crate) fn relations<R: RelationSchema>(self) -> Result<Vec<DraftRelation<R>>, PassError> {
        let schema = self.authorize::<R>()?;
        self.view
            .relations::<R>()
            .map_err(|source| PassError::Build {
                pass: self.pass.clone(),
                schema,
                source: Box::new(source),
            })
    }

    fn authorize<S: RowSchema>(self) -> Result<SchemaId, PassError> {
        let descriptor =
            self.registry
                .descriptor_for::<S>()
                .map_err(|source| PassError::SchemaAccess {
                    pass: self.pass.clone(),
                    schema: SchemaId::new(S::ID).ok(),
                    source: Box::new(source),
                })?;
        let schema = descriptor.id().clone();
        if !self.declared_reads.contains(&schema) {
            return Err(PassError::UndeclaredRead {
                pass: self.pass.clone(),
                schema,
            });
        }
        Ok(schema)
    }
}

/// The isolated delta exposed to a running pass.
///
/// The underlying builder is deliberately not exposed. Every mutation names a
/// typed schema, which is checked against the active pass's declaration before
/// the builder operation. If either the operation or the pass fails, the
/// scheduler drops the complete delta.
pub(crate) struct PassOutput<'a> {
    pass: &'a PassId,
    declared_reads: &'a BTreeSet<SchemaId>,
    declared_writes: &'a BTreeSet<SchemaId>,
    registry: &'a SchemaRegistry,
    delta: &'a mut ArtifactDbBuilder,
    touched: BTreeSet<SchemaId>,
}

impl<'a> PassOutput<'a> {
    fn new(
        pass: &'a PassId,
        declared_reads: &'a BTreeSet<SchemaId>,
        declared_writes: &'a BTreeSet<SchemaId>,
        registry: &'a SchemaRegistry,
        delta: &'a mut ArtifactDbBuilder,
    ) -> Self {
        Self {
            pass,
            declared_reads,
            declared_writes,
            registry,
            delta,
            touched: BTreeSet::new(),
        }
    }

    pub(crate) fn pass_id(&self) -> &PassId {
        self.pass
    }

    /// Creates fact metadata owned by the active pass.
    #[must_use]
    pub(crate) fn fact_meta(&self) -> FactMeta {
        FactMeta::new(self.pass.clone())
    }

    pub(crate) fn with_fact_owner<E: EntitySchema>(
        &self,
        meta: FactMeta,
        owner: &EntityHandle<E>,
    ) -> Result<FactMeta, PassError> {
        self.map_metadata::<E>(meta.with_owner(owner))
    }

    pub(crate) fn with_fact_anchor<E: EntitySchema>(
        &self,
        meta: FactMeta,
        anchor: &EntityHandle<E>,
    ) -> Result<FactMeta, PassError> {
        self.map_metadata::<E>(meta.with_anchor(anchor))
    }

    pub(crate) fn with_fact_provenance_root<E: EntitySchema>(
        &self,
        meta: FactMeta,
        root: &EntityHandle<E>,
    ) -> Result<FactMeta, PassError> {
        self.map_metadata::<E>(meta.with_provenance_root(root))
    }

    pub(crate) fn with_fact_requirement<R: RequirementSchema>(
        &self,
        meta: FactMeta,
        requirement: &RowHandle<R>,
    ) -> Result<FactMeta, PassError> {
        self.map_metadata::<R>(meta.with_requirement(requirement))
    }

    pub(crate) fn insert_entity<E: EntitySchema>(
        &mut self,
        entity: &E,
    ) -> Result<EntityHandle<E>, PassError> {
        self.write::<E, _>(|delta| delta.insert_entity(entity))
    }

    pub(crate) fn insert_fact<F: FactSchema>(
        &mut self,
        fact: &F,
        meta: FactMeta,
    ) -> Result<(), PassError> {
        if meta.producer() != self.pass {
            return Err(PassError::WrongFactProducer {
                pass: self.pass.clone(),
                declared: meta.producer().clone(),
            });
        }
        self.write::<F, _>(|delta| delta.insert_fact(fact, meta))
    }

    pub(crate) fn insert_requirement<R: RequirementSchema>(
        &mut self,
        requirement: &R,
    ) -> Result<RowHandle<R>, PassError> {
        self.write::<R, _>(|delta| delta.insert_requirement(requirement))
    }

    pub(crate) fn relate<R: RelationSchema>(
        &mut self,
        from: &EntityHandle<R::From>,
        to: &EntityHandle<R::To>,
        relation: &R,
    ) -> Result<(), PassError> {
        self.authorize_reference::<R::From>()?;
        self.authorize_reference::<R::To>()?;
        self.write::<R, _>(|delta| delta.relate(from, to, relation))
    }

    pub(crate) fn relate_with_source<R, A>(
        &mut self,
        from: &EntityHandle<R::From>,
        to: &EntityHandle<R::To>,
        source: &EntityHandle<A>,
        relation: &R,
    ) -> Result<(), PassError>
    where
        R: RelationSchema,
        A: EntitySchema,
    {
        self.authorize_reference::<R::From>()?;
        self.authorize_reference::<R::To>()?;
        self.authorize_reference::<A>()?;
        self.write::<R, _>(|delta| delta.relate_with_source(from, to, source, relation))
    }

    fn write<S, T>(
        &mut self,
        operation: impl FnOnce(&mut ArtifactDbBuilder) -> Result<T, BuildError>,
    ) -> Result<T, PassError>
    where
        S: RowSchema,
    {
        let descriptor =
            self.registry
                .descriptor_for::<S>()
                .map_err(|source| PassError::SchemaAccess {
                    pass: self.pass.clone(),
                    schema: SchemaId::new(S::ID).ok(),
                    source: Box::new(source),
                })?;
        let schema = descriptor.id().clone();
        if !self.declared_writes.contains(&schema) {
            return Err(PassError::UndeclaredWrite {
                pass: self.pass.clone(),
                schema,
            });
        }

        let value = operation(self.delta).map_err(|source| PassError::Build {
            pass: self.pass.clone(),
            schema: schema.clone(),
            source: Box::new(source),
        })?;
        self.touched.insert(schema);
        Ok(value)
    }

    fn map_metadata<S: RowSchema>(
        &self,
        result: Result<FactMeta, BuildError>,
    ) -> Result<FactMeta, PassError> {
        let schema = self.authorize_reference::<S>()?;
        result.map_err(|source| PassError::Build {
            pass: self.pass.clone(),
            schema,
            source: Box::new(source),
        })
    }

    fn authorize_reference<S: RowSchema>(&self) -> Result<SchemaId, PassError> {
        let descriptor =
            self.registry
                .descriptor_for::<S>()
                .map_err(|source| PassError::SchemaAccess {
                    pass: self.pass.clone(),
                    schema: SchemaId::new(S::ID).ok(),
                    source: Box::new(source),
                })?;
        let schema = descriptor.id().clone();
        if self.declared_reads.contains(&schema) || self.declared_writes.contains(&schema) {
            Ok(schema)
        } else {
            Err(PassError::UndeclaredRead {
                pass: self.pass.clone(),
                schema,
            })
        }
    }

    pub(crate) fn touched_schemas(&self) -> impl Iterator<Item = &SchemaId> {
        self.touched.iter()
    }
}

/// A failure produced while collecting one pass's delta.
#[derive(Debug)]
pub(crate) enum PassError {
    /// A pass attempted to read a table absent from its descriptor.
    UndeclaredRead { pass: PassId, schema: SchemaId },
    /// A pass attempted to write a table absent from its descriptor.
    UndeclaredWrite { pass: PassId, schema: SchemaId },
    /// A typed access did not match the compile-time schema registry.
    SchemaAccess {
        pass: PassId,
        schema: Option<SchemaId>,
        source: Box<SchemaRegistryError>,
    },
    /// The typed artifact builder rejected a row emitted by the pass.
    Build {
        pass: PassId,
        schema: SchemaId,
        source: Box<BuildError>,
    },
    /// Fact metadata attempted to attribute output to a different pass.
    WrongFactProducer { pass: PassId, declared: PassId },
    /// A pass-specific collection failure with stable human-readable context.
    Failed { message: String },
}

impl PassError {
    pub(crate) fn failed(message: impl Into<String>) -> Self {
        Self::Failed {
            message: message.into(),
        }
    }
}

impl Display for PassError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UndeclaredRead { pass, schema } => write!(
                formatter,
                "artifact pass {pass:?} attempted undeclared read from schema {schema:?}"
            ),
            Self::UndeclaredWrite { pass, schema } => write!(
                formatter,
                "artifact pass {pass:?} attempted undeclared write to schema {schema:?}"
            ),
            Self::SchemaAccess {
                pass,
                schema,
                source,
            } => {
                write!(formatter, "artifact pass {pass:?} used incompatible")?;
                if let Some(schema) = schema {
                    write!(formatter, " schema {schema:?}")?;
                } else {
                    formatter.write_str(" schema")?;
                }
                write!(formatter, ": {source}")
            }
            Self::Build {
                pass,
                schema,
                source,
            } => write!(
                formatter,
                "artifact pass {pass:?} could not write schema {schema:?}: {source}"
            ),
            Self::WrongFactProducer { pass, declared } => write!(
                formatter,
                "artifact pass {pass:?} cannot attribute a fact to pass {declared:?}"
            ),
            Self::Failed { message } => formatter.write_str(message),
        }
    }
}

impl Error for PassError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Build { source, .. } => Some(source.as_ref()),
            Self::SchemaAccess { source, .. } => Some(source.as_ref()),
            Self::UndeclaredRead { .. }
            | Self::UndeclaredWrite { .. }
            | Self::WrongFactProducer { .. }
            | Self::Failed { .. } => None,
        }
    }
}

/// A descriptor rejected while registering an artifact pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PassRegistrationError {
    DuplicatePassId {
        pass: PassId,
    },
    DuplicateProducer {
        schema: SchemaId,
        first: PassId,
        second: PassId,
    },
    DuplicateRead {
        pass: PassId,
        schema: SchemaId,
    },
    DuplicateWrite {
        pass: PassId,
        schema: SchemaId,
    },
    ReadWriteConflict {
        pass: PassId,
        schema: SchemaId,
    },
}

impl Display for PassRegistrationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicatePassId { pass } => {
                write!(formatter, "duplicate artifact pass ID {pass:?}")
            }
            Self::DuplicateProducer {
                schema,
                first,
                second,
            } => write!(
                formatter,
                "schema {schema:?} has ambiguous producers {first:?} and {second:?}"
            ),
            Self::DuplicateRead { pass, schema } => write!(
                formatter,
                "artifact pass {pass:?} declares schema {schema:?} as an input more than once"
            ),
            Self::DuplicateWrite { pass, schema } => write!(
                formatter,
                "artifact pass {pass:?} declares schema {schema:?} as an output more than once"
            ),
            Self::ReadWriteConflict { pass, schema } => write!(
                formatter,
                "artifact pass {pass:?} cannot read and write schema {schema:?} in one atomic pass"
            ),
        }
    }
}

impl Error for PassRegistrationError {}

/// A dependency graph that cannot be scheduled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PassScheduleError {
    MissingInput {
        pass: PassId,
        schema: SchemaId,
    },
    Cycle {
        passes: Vec<PassId>,
        schemas: Vec<SchemaId>,
    },
}

impl Display for PassScheduleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingInput { pass, schema } => write!(
                formatter,
                "artifact pass {pass:?} requires schema {schema:?}, but no producer or initial table provides it"
            ),
            Self::Cycle { passes, schemas } => write!(
                formatter,
                "artifact pass dependency cycle involves passes {passes:?} through schemas {schemas:?}"
            ),
        }
    }
}

impl Error for PassScheduleError {}

/// Error context added around a pass's isolated execution.
#[derive(Debug)]
pub(crate) struct PassRunError {
    pub(crate) pass: PassId,
    pub(crate) source: PassError,
}

impl Display for PassRunError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "artifact pass {:?} failed: {}",
            self.pass, self.source
        )
    }
}

impl Error for PassRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// Failure while scheduling, executing, or atomically committing a pass DAG.
#[derive(Debug)]
pub(crate) enum PassPipelineError {
    Schedule(PassScheduleError),
    Run(PassRunError),
    Commit {
        pass: PassId,
        source: Box<BuildError>,
    },
}

impl Display for PassPipelineError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schedule(source) => {
                write!(formatter, "artifact pass scheduling failed: {source}")
            }
            Self::Run(source) => source.fmt(formatter),
            Self::Commit { pass, source } => {
                write!(
                    formatter,
                    "artifact pass {pass:?} could not commit its output: {source}"
                )
            }
        }
    }
}

impl Error for PassPipelineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Schedule(source) => Some(source),
            Self::Run(source) => Some(source),
            Self::Commit { source, .. } => Some(source.as_ref()),
        }
    }
}

/// One pass paired with the single descriptor value captured from it.
///
/// Keeping the descriptor and pass in one opaque token prevents composition
/// validation from inspecting one declaration and the scheduler from storing
/// a later, potentially different declaration.
pub(super) struct CapturedArtifactPass<C: ?Sized> {
    descriptor: PassDescriptor,
    pass: Box<dyn ArtifactPass<C>>,
}

impl<C: ?Sized> CapturedArtifactPass<C> {
    pub(super) fn capture(pass: impl ArtifactPass<C> + 'static) -> Self {
        let pass: Box<dyn ArtifactPass<C>> = Box::new(pass);
        let descriptor = pass.descriptor();
        Self { descriptor, pass }
    }

    pub(super) fn descriptor(&self) -> &PassDescriptor {
        &self.descriptor
    }
}

/// Compile-time collection of artifact passes and their deterministic DAG.
pub(crate) struct ArtifactPassScheduler<C: ?Sized> {
    passes: BTreeMap<PassId, CapturedArtifactPass<C>>,
    producers: BTreeMap<SchemaId, PassId>,
}

impl<C: ?Sized> Default for ArtifactPassScheduler<C> {
    fn default() -> Self {
        Self {
            passes: BTreeMap::new(),
            producers: BTreeMap::new(),
        }
    }
}

impl<C: ?Sized> ArtifactPassScheduler<C> {
    pub(crate) fn register(
        &mut self,
        pass: impl ArtifactPass<C> + 'static,
    ) -> Result<(), PassRegistrationError> {
        self.register_captured(CapturedArtifactPass::capture(pass))
    }

    pub(super) fn register_captured(
        &mut self,
        captured: CapturedArtifactPass<C>,
    ) -> Result<(), PassRegistrationError> {
        let CapturedArtifactPass {
            mut descriptor,
            pass,
        } = captured;
        if self.passes.contains_key(&descriptor.id) {
            return Err(PassRegistrationError::DuplicatePassId {
                pass: descriptor.id,
            });
        }

        let reads = unique_declarations(&descriptor.id, &descriptor.reads, |pass, schema| {
            PassRegistrationError::DuplicateRead { pass, schema }
        })?;
        let writes = unique_declarations(&descriptor.id, &descriptor.writes, |pass, schema| {
            PassRegistrationError::DuplicateWrite { pass, schema }
        })?;

        if let Some(schema) = reads.intersection(&writes).next() {
            return Err(PassRegistrationError::ReadWriteConflict {
                pass: descriptor.id,
                schema: schema.clone(),
            });
        }

        // Descriptor vector order is not semantic. Canonicalizing it here also
        // makes structured missing-input errors independent of how a pack
        // assembled its declarations.
        descriptor.reads.sort();
        descriptor.writes.sort();

        for schema in &writes {
            if let Some(first) = self.producers.get(schema) {
                return Err(PassRegistrationError::DuplicateProducer {
                    schema: schema.clone(),
                    first: first.clone(),
                    second: descriptor.id,
                });
            }
        }

        for schema in writes {
            self.producers.insert(schema, descriptor.id.clone());
        }
        self.passes.insert(
            descriptor.id.clone(),
            CapturedArtifactPass { descriptor, pass },
        );
        Ok(())
    }

    pub(crate) fn descriptor(&self, pass: &PassId) -> Option<&PassDescriptor> {
        self.passes
            .get(pass)
            .map(|registered| &registered.descriptor)
    }

    pub(crate) fn descriptors(&self) -> impl Iterator<Item = &PassDescriptor> {
        self.passes
            .values()
            .map(|registered| &registered.descriptor)
    }

    /// Runs the complete stable pass order, committing one successful delta at
    /// a time. A failed pass never mutates `committed`.
    pub(crate) fn run_all(
        &mut self,
        cx: &C,
        committed: &mut ArtifactDbBuilder,
        registry: &SchemaRegistry,
    ) -> Result<(), PassPipelineError> {
        let initial_schemas = committed.schema_ids().cloned().collect::<BTreeSet<_>>();
        let order = self
            .schedule(&initial_schemas)
            .map_err(PassPipelineError::Schedule)?;
        for pass in order {
            let delta = self
                .run_pass_to_delta(&pass, cx, committed.draft_view(), registry)
                .map_err(PassPipelineError::Run)?;
            let mut candidate = committed.clone();
            candidate
                .merge(delta)
                .and_then(|()| candidate.validate_pending(registry))
                .map_err(|source| PassPipelineError::Commit {
                    pass,
                    source: Box::new(source),
                })?;
            *committed = candidate;
        }
        Ok(())
    }

    /// Computes a stable topological order without executing any pass.
    pub(crate) fn schedule(
        &self,
        initial_schemas: &BTreeSet<SchemaId>,
    ) -> Result<Vec<PassId>, PassScheduleError> {
        let adjacency = self.dependency_graph(initial_schemas)?;
        let mut indegree = self
            .passes
            .keys()
            .cloned()
            .map(|pass| (pass, 0usize))
            .collect::<BTreeMap<_, _>>();

        for edges in adjacency.values() {
            for consumer in edges.keys() {
                *indegree
                    .get_mut(consumer)
                    .expect("dependency graph only contains registered passes") += 1;
            }
        }

        let mut ready = indegree
            .iter()
            .filter_map(|(pass, degree)| (*degree == 0).then_some(pass.clone()))
            .collect::<BTreeSet<_>>();
        let mut order = Vec::with_capacity(self.passes.len());

        while let Some(pass) = ready.pop_first() {
            order.push(pass.clone());
            if let Some(edges) = adjacency.get(&pass) {
                for consumer in edges.keys() {
                    let degree = indegree
                        .get_mut(consumer)
                        .expect("dependency graph only contains registered passes");
                    *degree -= 1;
                    if *degree == 0 {
                        ready.insert(consumer.clone());
                    }
                }
            }
        }

        if order.len() != self.passes.len() {
            let (passes, schemas) = find_cycle(&adjacency)
                .expect("an incomplete topological order must contain a dependency cycle");
            return Err(PassScheduleError::Cycle { passes, schemas });
        }

        Ok(order)
    }

    /// Runs one scheduled pass into a fresh isolated delta.
    ///
    /// On error, this function drops the delta; no API exposes the partially
    /// populated builder. The caller may merge the returned builder into the
    /// committed database only after this method succeeds.
    pub(crate) fn run_pass_to_delta(
        &mut self,
        pass_id: &PassId,
        cx: &C,
        input: ArtifactDbDraftView<'_>,
        registry: &SchemaRegistry,
    ) -> Result<ArtifactDbBuilder, PassRunError> {
        let registered = self
            .passes
            .get_mut(pass_id)
            .expect("only pass IDs returned by schedule may be executed");
        let declared_writes = registered
            .descriptor
            .writes
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let declared_reads = registered
            .descriptor
            .reads
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut delta = ArtifactDbBuilder::new();
        for schema in &declared_writes {
            let descriptor = registry.descriptor(schema).ok_or_else(|| PassRunError {
                pass: pass_id.clone(),
                source: PassError::SchemaAccess {
                    pass: pass_id.clone(),
                    schema: Some(schema.clone()),
                    source: Box::new(SchemaRegistryError::SchemaNotRegistered {
                        schema: schema.clone(),
                        rust_type: "artifact pass descriptor",
                    }),
                },
            })?;
            delta
                .declare_table(descriptor)
                .map_err(|source| PassRunError {
                    pass: pass_id.clone(),
                    source: PassError::Build {
                        pass: pass_id.clone(),
                        schema: schema.clone(),
                        source: Box::new(source),
                    },
                })?;
        }
        let input = PassInput::new(&registered.descriptor.id, &declared_reads, registry, input);
        let mut output = PassOutput::new(
            &registered.descriptor.id,
            &declared_reads,
            &declared_writes,
            registry,
            &mut delta,
        );

        registered
            .pass
            .run(cx, input, &mut output)
            .map_err(|source| PassRunError {
                pass: pass_id.clone(),
                source,
            })?;
        Ok(delta)
    }

    fn dependency_graph(
        &self,
        initial_schemas: &BTreeSet<SchemaId>,
    ) -> Result<DependencyGraph, PassScheduleError> {
        let mut adjacency = self
            .passes
            .keys()
            .cloned()
            .map(|pass| (pass, BTreeMap::new()))
            .collect::<DependencyGraph>();

        for registered in self.passes.values() {
            for schema in &registered.descriptor.reads {
                if let Some(producer) = self.producers.get(schema) {
                    adjacency
                        .get_mut(producer)
                        .expect("every producer is a registered pass")
                        .entry(registered.descriptor.id.clone())
                        .or_insert_with(BTreeSet::new)
                        .insert(schema.clone());
                } else if !initial_schemas.contains(schema) {
                    return Err(PassScheduleError::MissingInput {
                        pass: registered.descriptor.id.clone(),
                        schema: schema.clone(),
                    });
                }
            }
        }
        Ok(adjacency)
    }
}

type DependencyGraph = BTreeMap<PassId, BTreeMap<PassId, BTreeSet<SchemaId>>>;

fn unique_declarations(
    pass: &PassId,
    declarations: &[SchemaId],
    duplicate: impl Fn(PassId, SchemaId) -> PassRegistrationError,
) -> Result<BTreeSet<SchemaId>, PassRegistrationError> {
    let mut unique = BTreeSet::new();
    for schema in declarations {
        if !unique.insert(schema.clone()) {
            return Err(duplicate(pass.clone(), schema.clone()));
        }
    }
    Ok(unique)
}

fn find_cycle(graph: &DependencyGraph) -> Option<(Vec<PassId>, Vec<SchemaId>)> {
    fn visit(
        pass: &PassId,
        graph: &DependencyGraph,
        state: &mut BTreeMap<PassId, VisitState>,
        stack: &mut Vec<PassId>,
    ) -> Option<(Vec<PassId>, Vec<SchemaId>)> {
        state.insert(pass.clone(), VisitState::Active);
        stack.push(pass.clone());

        for next in graph.get(pass).into_iter().flat_map(|edges| edges.keys()) {
            match state.get(next).copied().unwrap_or(VisitState::Unvisited) {
                VisitState::Unvisited => {
                    if let Some(cycle) = visit(next, graph, state, stack) {
                        return Some(cycle);
                    }
                }
                VisitState::Active => {
                    let start = stack
                        .iter()
                        .position(|active| active == next)
                        .expect("an active pass is present in the DFS stack");
                    let passes = stack[start..].to_vec();
                    let mut schemas = BTreeSet::new();
                    for edge in passes.windows(2) {
                        schemas.extend(graph[&edge[0]][&edge[1]].iter().cloned());
                    }
                    schemas.extend(
                        graph[passes.last().expect("cycle is nonempty")][next]
                            .iter()
                            .cloned(),
                    );
                    return Some((passes, schemas.into_iter().collect()));
                }
                VisitState::Finished => {}
            }
        }

        let popped = stack.pop();
        debug_assert_eq!(popped.as_ref(), Some(pass));
        state.insert(pass.clone(), VisitState::Finished);
        None
    }

    let mut state = BTreeMap::new();
    let mut stack = Vec::new();
    for pass in graph.keys() {
        if state.get(pass).copied().unwrap_or(VisitState::Unvisited) == VisitState::Unvisited
            && let Some(cycle) = visit(pass, graph, &mut state, &mut stack)
        {
            return Some(cycle);
        }
    }
    None
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum VisitState {
    Unvisited,
    Active,
    Finished,
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::analysis::facts::registry::SchemaRegistry;
    use crate::analysis::facts::schema::{EntitySchema, FactSchema, RelationSchema};

    struct NoopPass(PassDescriptor);

    impl ArtifactPass<()> for NoopPass {
        fn descriptor(&self) -> PassDescriptor {
            self.0.clone()
        }

        fn run(
            &mut self,
            _cx: &(),
            _input: PassInput<'_>,
            _output: &mut PassOutput<'_>,
        ) -> Result<(), PassError> {
            Ok(())
        }
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct SampleFact {
        value: String,
    }

    impl RowSchema for SampleFact {
        const ID: &'static str = "sample.pass.fact";
        const VERSION: u32 = 1;
    }

    impl FactSchema for SampleFact {}

    #[derive(Clone, Serialize, Deserialize)]
    struct OtherFact {
        value: String,
    }

    impl RowSchema for OtherFact {
        const ID: &'static str = "sample.pass.other-fact";
        const VERSION: u32 = 1;
    }

    impl FactSchema for OtherFact {}

    #[derive(Clone, Serialize, Deserialize)]
    struct SampleNode {
        name: String,
    }

    impl RowSchema for SampleNode {
        const ID: &'static str = "sample.pass.node";
        const VERSION: u32 = 1;
    }

    impl EntitySchema for SampleNode {
        type Key = String;

        fn key(&self) -> Self::Key {
            self.name.clone()
        }
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct SampleEdge;

    impl RowSchema for SampleEdge {
        const ID: &'static str = "sample.pass.edge";
        const VERSION: u32 = 1;
    }

    impl RelationSchema for SampleEdge {
        type From = SampleNode;
        type To = SampleNode;
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct ImpostorFact {
        value: String,
    }

    impl RowSchema for ImpostorFact {
        const ID: &'static str = SampleFact::ID;
        const VERSION: u32 = SampleFact::VERSION;
    }

    impl FactSchema for ImpostorFact {}

    struct FactWritingPass {
        descriptor: PassDescriptor,
        fail_after_write: bool,
    }

    impl ArtifactPass<()> for FactWritingPass {
        fn descriptor(&self) -> PassDescriptor {
            self.descriptor.clone()
        }

        fn run(
            &mut self,
            _cx: &(),
            _input: PassInput<'_>,
            output: &mut PassOutput<'_>,
        ) -> Result<(), PassError> {
            let meta = output.fact_meta();
            output.insert_fact(
                &SampleFact {
                    value: String::from("collected"),
                },
                meta,
            )?;
            if self.fail_after_write {
                return Err(PassError::failed("intentional failure after write"));
            }
            Ok(())
        }
    }

    struct OtherFactWritingPass;

    impl ArtifactPass<()> for OtherFactWritingPass {
        fn descriptor(&self) -> PassDescriptor {
            PassDescriptor::new(pass_id("sample.pass.a")).with_writes([schema_id(OtherFact::ID)])
        }

        fn run(
            &mut self,
            _cx: &(),
            _input: PassInput<'_>,
            output: &mut PassOutput<'_>,
        ) -> Result<(), PassError> {
            let meta = output.fact_meta();
            output.insert_fact(
                &OtherFact {
                    value: String::from("other"),
                },
                meta,
            )
        }
    }

    struct UndeclaredReadingPass;

    impl ArtifactPass<()> for UndeclaredReadingPass {
        fn descriptor(&self) -> PassDescriptor {
            PassDescriptor::new(pass_id("sample.pass.undeclared-read"))
        }

        fn run(
            &mut self,
            _cx: &(),
            input: PassInput<'_>,
            _output: &mut PassOutput<'_>,
        ) -> Result<(), PassError> {
            input.table::<SampleFact>().map(drop)
        }
    }

    struct ImpostorWritingPass;

    impl ArtifactPass<()> for ImpostorWritingPass {
        fn descriptor(&self) -> PassDescriptor {
            PassDescriptor::new(pass_id("sample.pass.impostor"))
                .with_writes([schema_id(SampleFact::ID)])
        }

        fn run(
            &mut self,
            _cx: &(),
            _input: PassInput<'_>,
            output: &mut PassOutput<'_>,
        ) -> Result<(), PassError> {
            let meta = output.fact_meta();
            output.insert_fact(
                &ImpostorFact {
                    value: String::from("wrong Rust type"),
                },
                meta,
            )
        }
    }

    struct DanglingRelationPass;

    impl ArtifactPass<()> for DanglingRelationPass {
        fn descriptor(&self) -> PassDescriptor {
            PassDescriptor::new(pass_id("sample.pass.dangling"))
                .with_writes([schema_id(SampleNode::ID), schema_id(SampleEdge::ID)])
        }

        fn run(
            &mut self,
            _cx: &(),
            _input: PassInput<'_>,
            output: &mut PassOutput<'_>,
        ) -> Result<(), PassError> {
            output.relate(
                &EntityHandle::new(String::from("missing-from")),
                &EntityHandle::new(String::from("missing-to")),
                &SampleEdge,
            )
        }
    }

    fn pass_id(value: &str) -> PassId {
        PassId::new(value).expect("test pass ID is valid")
    }

    fn schema_id(value: &str) -> SchemaId {
        SchemaId::new(value).expect("test schema ID is valid")
    }

    fn test_registry() -> SchemaRegistry {
        let mut registry = SchemaRegistry::new();
        registry.register_fact::<SampleFact>().unwrap();
        registry.register_fact::<OtherFact>().unwrap();
        registry.register_entity::<SampleNode>().unwrap();
        registry.register_relation::<SampleEdge>().unwrap();
        registry
    }

    fn pass(id: &str, reads: &[&str], writes: &[&str]) -> NoopPass {
        NoopPass(
            PassDescriptor::new(pass_id(id))
                .with_reads(reads.iter().map(|schema| schema_id(schema)))
                .with_writes(writes.iter().map(|schema| schema_id(schema))),
        )
    }

    #[test]
    fn independent_passes_are_scheduled_by_stable_id() {
        let mut scheduler = ArtifactPassScheduler::<()>::default();
        scheduler
            .register(pass("test.z", &[], &["test.output-z"]))
            .expect("register z");
        scheduler
            .register(pass("test.a", &[], &["test.output-a"]))
            .expect("register a");

        let order = scheduler.schedule(&BTreeSet::new()).expect("schedule");

        assert_eq!(order, vec![pass_id("test.a"), pass_id("test.z")]);
    }

    #[test]
    fn producer_is_scheduled_before_consumer_regardless_of_registration_order() {
        let mut scheduler = ArtifactPassScheduler::<()>::default();
        scheduler
            .register(pass(
                "test.consumer",
                &["test.produced"],
                &["test.consumed"],
            ))
            .expect("register consumer");
        scheduler
            .register(pass("test.producer", &[], &["test.produced"]))
            .expect("register producer");

        let order = scheduler.schedule(&BTreeSet::new()).expect("schedule");

        assert_eq!(
            order,
            vec![pass_id("test.producer"), pass_id("test.consumer")]
        );
    }

    #[test]
    fn missing_input_reports_pass_and_schema() {
        let mut scheduler = ArtifactPassScheduler::<()>::default();
        scheduler
            .register(pass("test.consumer", &["test.missing"], &[]))
            .expect("register consumer");

        let error = scheduler
            .schedule(&BTreeSet::new())
            .expect_err("missing producer must fail");

        assert_eq!(
            error,
            PassScheduleError::MissingInput {
                pass: pass_id("test.consumer"),
                schema: schema_id("test.missing"),
            }
        );
    }

    #[test]
    fn initial_table_satisfies_a_read_without_a_registered_producer() {
        let mut scheduler = ArtifactPassScheduler::<()>::default();
        scheduler
            .register(pass("test.consumer", &["test.initial"], &[]))
            .expect("register consumer");

        let order = scheduler
            .schedule(&BTreeSet::from([schema_id("test.initial")]))
            .expect("initial schema satisfies dependency");

        assert_eq!(order, vec![pass_id("test.consumer")]);
    }

    #[test]
    fn duplicate_pass_ids_are_rejected_before_graph_construction() {
        let mut scheduler = ArtifactPassScheduler::<()>::default();
        scheduler
            .register(pass("test.same", &[], &["test.first"]))
            .expect("register first pass");

        let error = scheduler
            .register(pass("test.same", &[], &["test.second"]))
            .expect_err("duplicate pass ID must fail");

        assert_eq!(
            error,
            PassRegistrationError::DuplicatePassId {
                pass: pass_id("test.same")
            }
        );
    }

    #[test]
    fn duplicate_schema_producers_are_rejected() {
        let mut scheduler = ArtifactPassScheduler::<()>::default();
        scheduler
            .register(pass("test.first", &[], &["test.shared"]))
            .expect("register first producer");

        let error = scheduler
            .register(pass("test.second", &[], &["test.shared"]))
            .expect_err("ambiguous producer must fail");

        assert_eq!(
            error,
            PassRegistrationError::DuplicateProducer {
                schema: schema_id("test.shared"),
                first: pass_id("test.first"),
                second: pass_id("test.second"),
            }
        );
    }

    #[test]
    fn one_pass_cannot_read_its_uncommitted_output() {
        let mut scheduler = ArtifactPassScheduler::<()>::default();

        let error = scheduler
            .register(pass("test.conflict", &["test.shared"], &["test.shared"]))
            .expect_err("read/write conflict must fail");

        assert_eq!(
            error,
            PassRegistrationError::ReadWriteConflict {
                pass: pass_id("test.conflict"),
                schema: schema_id("test.shared"),
            }
        );
    }

    #[test]
    fn cycle_reports_stable_pass_and_schema_context() {
        let mut scheduler = ArtifactPassScheduler::<()>::default();
        scheduler
            .register(pass("test.a", &["test.from-b"], &["test.from-a"]))
            .expect("register a");
        scheduler
            .register(pass("test.b", &["test.from-a"], &["test.from-b"]))
            .expect("register b");

        let error = scheduler
            .schedule(&BTreeSet::new())
            .expect_err("cycle must fail");

        assert_eq!(
            error,
            PassScheduleError::Cycle {
                passes: vec![pass_id("test.a"), pass_id("test.b")],
                schemas: vec![schema_id("test.from-a"), schema_id("test.from-b")],
            }
        );
    }

    #[test]
    fn pass_output_rejects_a_typed_write_absent_from_the_descriptor() {
        let id = pass_id("sample.pass.undeclared");
        let mut scheduler = ArtifactPassScheduler::<()>::default();
        scheduler
            .register(FactWritingPass {
                descriptor: PassDescriptor::new(id.clone()),
                fail_after_write: false,
            })
            .expect("register pass");
        let committed = ArtifactDbBuilder::new();
        let registry = test_registry();

        let error = scheduler
            .run_pass_to_delta(&id, &(), committed.draft_view(), &registry)
            .expect_err("undeclared typed write must fail");

        assert!(matches!(
            error.source,
            PassError::UndeclaredWrite { pass, schema }
                if pass == id && schema == schema_id(SampleFact::ID)
        ));
    }

    #[test]
    fn pass_input_rejects_a_typed_read_absent_from_the_descriptor() {
        let id = pass_id("sample.pass.undeclared-read");
        let mut scheduler = ArtifactPassScheduler::<()>::default();
        scheduler.register(UndeclaredReadingPass).unwrap();
        let mut committed = ArtifactDbBuilder::new();
        committed
            .insert_fact(
                &SampleFact {
                    value: String::from("available"),
                },
                FactMeta::new(pass_id("sample.pass.initial")),
            )
            .unwrap();
        let registry = test_registry();

        let error = scheduler
            .run_pass_to_delta(&id, &(), committed.draft_view(), &registry)
            .expect_err("undeclared typed read must fail");

        assert!(matches!(
            error.source,
            PassError::UndeclaredRead { pass, schema }
                if pass == id && schema == schema_id(SampleFact::ID)
        ));
    }

    #[test]
    fn pass_output_rejects_a_rust_type_impersonating_a_registered_schema() {
        let id = pass_id("sample.pass.impostor");
        let mut scheduler = ArtifactPassScheduler::<()>::default();
        scheduler.register(ImpostorWritingPass).unwrap();
        let committed = ArtifactDbBuilder::new();
        let registry = test_registry();

        let error = scheduler
            .run_pass_to_delta(&id, &(), committed.draft_view(), &registry)
            .expect_err("schema IDs do not authorize a different Rust row type");

        assert!(matches!(error.source, PassError::SchemaAccess { .. }));
    }

    #[test]
    fn successful_pass_returns_its_isolated_delta() {
        let id = pass_id("sample.pass.success");
        let mut scheduler = ArtifactPassScheduler::<()>::default();
        scheduler
            .register(FactWritingPass {
                descriptor: PassDescriptor::new(id.clone())
                    .with_writes([schema_id(SampleFact::ID)]),
                fail_after_write: false,
            })
            .expect("register pass");
        let committed = ArtifactDbBuilder::new();
        let registry = test_registry();

        let delta = scheduler
            .run_pass_to_delta(&id, &(), committed.draft_view(), &registry)
            .expect("successful pass returns delta");

        assert_eq!(
            delta
                .draft_view()
                .table::<SampleFact>()
                .expect("decode pending facts")
                .len(),
            1
        );
    }

    #[test]
    fn failed_pass_does_not_return_its_partially_written_delta() {
        let id = pass_id("sample.pass.atomic-failure");
        let mut scheduler = ArtifactPassScheduler::<()>::default();
        scheduler
            .register(FactWritingPass {
                descriptor: PassDescriptor::new(id.clone())
                    .with_writes([schema_id(SampleFact::ID)]),
                fail_after_write: true,
            })
            .expect("register pass");
        let committed = ArtifactDbBuilder::new();
        let registry = test_registry();

        let result = scheduler.run_pass_to_delta(&id, &(), committed.draft_view(), &registry);

        assert!(matches!(
            result,
            Err(PassRunError {
                source: PassError::Failed { .. },
                ..
            })
        ));
    }

    #[test]
    fn run_all_preserves_committed_rows_when_a_pass_fails() {
        let id = pass_id("sample.pass.run-all-failure");
        let mut scheduler = ArtifactPassScheduler::<()>::default();
        scheduler
            .register(FactWritingPass {
                descriptor: PassDescriptor::new(id).with_writes([schema_id(SampleFact::ID)]),
                fail_after_write: true,
            })
            .unwrap();
        let mut committed = ArtifactDbBuilder::new();
        committed
            .insert_fact(
                &SampleFact {
                    value: String::from("already committed"),
                },
                FactMeta::new(pass_id("sample.pass.initial")),
            )
            .unwrap();

        let registry = test_registry();
        let result = scheduler.run_all(&(), &mut committed, &registry);

        assert!(matches!(result, Err(PassPipelineError::Run(_))));
        let facts = committed.draft_view().table::<SampleFact>().unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].value, "already committed");
    }

    #[test]
    fn run_all_rejects_a_successful_delta_with_dangling_provenance() {
        let id = pass_id("sample.pass.dangling");
        let mut scheduler = ArtifactPassScheduler::<()>::default();
        scheduler.register(DanglingRelationPass).unwrap();
        let mut committed = ArtifactDbBuilder::new();
        let registry = test_registry();

        let error = scheduler
            .run_all(&(), &mut committed, &registry)
            .expect_err("a dangling successful delta must not commit");

        assert!(matches!(
            error,
            PassPipelineError::Commit { pass, .. } if pass == id
        ));
        assert!(!committed.draft_view().contains_schema::<SampleEdge>());
    }

    #[test]
    fn final_bytes_do_not_depend_on_pass_registration_order() {
        fn build(reverse: bool) -> Vec<u8> {
            let z = FactWritingPass {
                descriptor: PassDescriptor::new(pass_id("sample.pass.z"))
                    .with_writes([schema_id(SampleFact::ID)]),
                fail_after_write: false,
            };
            let mut scheduler = ArtifactPassScheduler::<()>::default();
            if reverse {
                scheduler.register(z).unwrap();
                scheduler.register(OtherFactWritingPass).unwrap();
            } else {
                scheduler.register(OtherFactWritingPass).unwrap();
                scheduler.register(z).unwrap();
            }
            let mut committed = ArtifactDbBuilder::new();
            let schemas = test_registry();
            scheduler.run_all(&(), &mut committed, &schemas).unwrap();
            serde_json::to_vec(&committed.finalize(&schemas).unwrap()).unwrap()
        }

        assert_eq!(build(false), build(true));
    }
}
