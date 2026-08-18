//! Stable dependency scheduling and atomic execution of evaluation rules.

use std::any::type_name;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use super::super::composition::{
    CompositionRelationBuilder, CompositionRelationRegistry, WorkspaceEvaluationView,
};
use super::super::encoded::TableKind;
use super::super::registry::SchemaRegistry;
use super::super::schema::{DerivedSchema, IssueSchema, PassId, RowSchema, SchemaId};
use super::super::view::ArtifactDbView;
use super::super::workspace::{ScopedEntityRef, WorkspaceFactView};
use super::model::EvaluationRoot;
use super::rule::{
    EvaluationCx, EvaluationInput, EvaluationOutput, EvaluationReferenceValidator, EvaluationRule,
    RuleError, WorkspaceLookup,
};
use super::store::{EvaluationDb, EvaluationStorageError};

type SchemaValidator = fn(&SchemaRegistry) -> Result<(), String>;
type ArtifactInputAvailability = for<'a> fn(&WorkspaceFactView<'a>, TableKind) -> bool;

#[derive(Clone)]
struct SchemaDeclaration {
    id: SchemaId,
    rust_type: &'static str,
    validate: SchemaValidator,
    artifact_available: ArtifactInputAvailability,
    output_kind: Option<TableKind>,
}

impl SchemaDeclaration {
    fn row<S: RowSchema>() -> Self {
        Self {
            id: SchemaId::new(S::ID).expect("evaluation schemas must declare valid stable IDs"),
            rust_type: type_name::<S>(),
            validate: validate_schema::<S>,
            artifact_available: artifact_input_available::<S>,
            output_kind: None,
        }
    }

    fn output<S: RowSchema>(kind: TableKind) -> Self {
        let mut declaration = Self::row::<S>();
        declaration.output_kind = Some(kind);
        declaration
    }

    fn access(&self) -> RuleSchemaAccess {
        match self.output_kind {
            None => RuleSchemaAccess::Read,
            Some(TableKind::Derived) => RuleSchemaAccess::WriteDerived,
            Some(TableKind::Issue) => RuleSchemaAccess::WriteIssue,
            Some(kind) => unreachable!("{kind:?} is not an evaluation output kind"),
        }
    }
}

impl Debug for SchemaDeclaration {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SchemaDeclaration")
            .field("id", &self.id)
            .field("rust_type", &self.rust_type)
            .field("output_kind", &self.output_kind)
            .finish_non_exhaustive()
    }
}

fn validate_schema<S: RowSchema>(registry: &SchemaRegistry) -> Result<(), String> {
    registry
        .descriptor_for::<S>()
        .map(drop)
        .map_err(|error| error.to_string())
}

fn artifact_input_available<S: RowSchema>(
    workspace: &WorkspaceFactView<'_>,
    expected: TableKind,
) -> bool {
    workspace.all_artifacts_contain_typed_table::<S>(expected)
}

/// Static typed dependency declaration for one root-specific evaluation rule.
#[derive(Clone, Debug)]
pub(crate) struct RuleDescriptor {
    id: PassId,
    reads: Vec<SchemaDeclaration>,
    writes: Vec<SchemaDeclaration>,
}

impl RuleDescriptor {
    #[must_use]
    pub(crate) fn new(id: PassId) -> Self {
        Self {
            id,
            reads: Vec::new(),
            writes: Vec::new(),
        }
    }

    #[must_use]
    pub(crate) const fn id(&self) -> &PassId {
        &self.id
    }

    #[must_use]
    pub(crate) fn read<S: RowSchema>(mut self) -> Self {
        self.reads.push(SchemaDeclaration::row::<S>());
        self
    }

    #[must_use]
    pub(crate) fn write_issue<I: IssueSchema>(mut self) -> Self {
        self.writes
            .push(SchemaDeclaration::output::<I>(TableKind::Issue));
        self
    }

    #[must_use]
    pub(crate) fn write_derived<D: DerivedSchema>(mut self) -> Self {
        self.writes
            .push(SchemaDeclaration::output::<D>(TableKind::Derived));
        self
    }

    pub(crate) fn reads(&self) -> impl ExactSizeIterator<Item = &SchemaId> {
        self.reads.iter().map(|declaration| &declaration.id)
    }

    pub(crate) fn writes(&self) -> impl ExactSizeIterator<Item = &SchemaId> {
        self.writes.iter().map(|declaration| &declaration.id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuleSchemaAccess {
    Read,
    WriteDerived,
    WriteIssue,
}

impl Display for RuleSchemaAccess {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Read => "read",
            Self::WriteDerived => "write derived row",
            Self::WriteIssue => "write issue",
        })
    }
}

/// Registration failure for an evaluation rule or its typed declarations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RuleRegistrationError {
    DuplicateRuleId {
        rule: PassId,
    },
    DuplicateRead {
        rule: PassId,
        schema: SchemaId,
    },
    DuplicateWrite {
        rule: PassId,
        schema: SchemaId,
    },
    ReadWriteConflict {
        rule: PassId,
        schema: SchemaId,
    },
    InvalidDeclaration {
        rule: PassId,
        schema: SchemaId,
        access: RuleSchemaAccess,
        rust_type: &'static str,
        reason: String,
    },
    OutputKindMismatch {
        rule: PassId,
        schema: SchemaId,
        expected: TableKind,
        found: TableKind,
    },
}

impl Display for RuleRegistrationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateRuleId { rule } => write!(formatter, "duplicate evaluation rule {rule}"),
            Self::DuplicateRead { rule, schema } => write!(
                formatter,
                "evaluation rule {rule} declares read schema {schema} more than once"
            ),
            Self::DuplicateWrite { rule, schema } => write!(
                formatter,
                "evaluation rule {rule} declares output schema {schema} more than once"
            ),
            Self::ReadWriteConflict { rule, schema } => write!(
                formatter,
                "evaluation rule {rule} cannot read and write schema {schema} atomically"
            ),
            Self::InvalidDeclaration {
                rule,
                schema,
                access,
                rust_type,
                reason,
            } => write!(
                formatter,
                "evaluation rule {rule} cannot {access} schema {schema} as {rust_type}: {reason}"
            ),
            Self::OutputKindMismatch {
                rule,
                schema,
                expected,
                found,
            } => write!(
                formatter,
                "evaluation rule {rule} declares {found:?} schema {schema} as a {expected:?} output"
            ),
        }
    }
}

impl Error for RuleRegistrationError {}

/// A rule graph that cannot be evaluated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RuleScheduleError {
    MissingInput {
        rule: PassId,
        schema: SchemaId,
    },
    Cycle {
        rules: Vec<PassId>,
        schemas: Vec<SchemaId>,
    },
}

impl Display for RuleScheduleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingInput { rule, schema } => write!(
                formatter,
                "evaluation rule {rule} requires evaluation schema {schema}, but no rule produces it"
            ),
            Self::Cycle { rules, schemas } => write!(
                formatter,
                "evaluation rule dependency cycle involves {rules:?} through {schemas:?}"
            ),
        }
    }
}

impl Error for RuleScheduleError {}

#[derive(Debug)]
pub(crate) struct RuleRunError {
    pub(crate) rule: PassId,
    pub(crate) source: RuleError,
}

impl Display for RuleRunError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "evaluation rule {} failed: {}",
            self.rule, self.source
        )
    }
}

impl Error for RuleRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// Scheduling, execution, or atomic-commit failure for one root evaluation.
#[derive(Debug)]
pub(crate) enum EvaluationPipelineError {
    InvalidRoot {
        root: ScopedEntityRef,
        reason: String,
    },
    RootContextMismatch {
        expected: Box<EvaluationRoot>,
        found: Box<EvaluationRoot>,
    },
    WorkspaceContext {
        reason: String,
    },
    Schedule(RuleScheduleError),
    Run(RuleRunError),
    Commit {
        rule: PassId,
        source: EvaluationStorageError,
    },
}

impl Display for EvaluationPipelineError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRoot { root, reason } => write!(
                formatter,
                "evaluation root `{}`/`{}`:{} is invalid: {reason}",
                root.scope(),
                root.entity().schema,
                root.entity().row
            ),
            Self::RootContextMismatch { expected, found } => write!(
                formatter,
                "evaluation database belongs to root `{}`/`{}`:{} in domain {}, not root `{}`/`{}`:{} in domain {}",
                found.entity.scope(),
                found.entity.entity().schema,
                found.entity.entity().row,
                found.domain.as_str(),
                expected.entity.scope(),
                expected.entity.entity().schema,
                expected.entity.entity().row,
                expected.domain.as_str()
            ),
            Self::WorkspaceContext { reason } => {
                write!(formatter, "invalid workspace evaluation context: {reason}")
            }
            Self::Schedule(source) => write!(formatter, "evaluation scheduling failed: {source}"),
            Self::Run(source) => Display::fmt(source, formatter),
            Self::Commit { rule, source } => {
                write!(
                    formatter,
                    "evaluation rule {rule} could not commit output: {source}"
                )
            }
        }
    }
}

impl Error for EvaluationPipelineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Schedule(source) => Some(source),
            Self::Run(source) => Some(source),
            Self::Commit { source, .. } => Some(source),
            Self::InvalidRoot { .. }
            | Self::RootContextMismatch { .. }
            | Self::WorkspaceContext { .. } => None,
        }
    }
}

struct RegisteredRule<C: ?Sized> {
    descriptor: RuleDescriptor,
    rule: Box<dyn EvaluationRule<C>>,
}

/// Deterministic compile-time registry and scheduler for evaluation rules.
pub(crate) struct EvaluationRuleScheduler<C: ?Sized> {
    rules: BTreeMap<PassId, RegisteredRule<C>>,
    producers: BTreeMap<SchemaId, BTreeSet<PassId>>,
    schema_kinds: BTreeMap<SchemaId, TableKind>,
}

impl<C: ?Sized> Default for EvaluationRuleScheduler<C> {
    fn default() -> Self {
        Self {
            rules: BTreeMap::new(),
            producers: BTreeMap::new(),
            schema_kinds: BTreeMap::new(),
        }
    }
}

impl<C: ?Sized> EvaluationRuleScheduler<C> {
    pub(crate) fn register(
        &mut self,
        registry: &SchemaRegistry,
        rule: impl EvaluationRule<C> + 'static,
    ) -> Result<(), RuleRegistrationError> {
        self.register_boxed(registry, Box::new(rule))
    }

    fn register_boxed(
        &mut self,
        registry: &SchemaRegistry,
        rule: Box<dyn EvaluationRule<C>>,
    ) -> Result<(), RuleRegistrationError> {
        let descriptor = rule.descriptor();
        if self.rules.contains_key(&descriptor.id) {
            return Err(RuleRegistrationError::DuplicateRuleId {
                rule: descriptor.id,
            });
        }
        let reads = validate_declarations(registry, &descriptor.id, &descriptor.reads)?;
        let writes = validate_declarations(registry, &descriptor.id, &descriptor.writes)?;
        for declaration in &descriptor.writes {
            let kind = registry
                .descriptor(&declaration.id)
                .expect("typed declarations were validated")
                .kind();
            let expected = declaration
                .output_kind
                .expect("write declarations always carry an output kind");
            if kind != expected {
                return Err(RuleRegistrationError::OutputKindMismatch {
                    rule: descriptor.id.clone(),
                    schema: declaration.id.clone(),
                    expected,
                    found: kind,
                });
            }
        }
        if let Some(schema) = reads.intersection(&writes).next() {
            return Err(RuleRegistrationError::ReadWriteConflict {
                rule: descriptor.id,
                schema: schema.clone(),
            });
        }
        for declaration in descriptor.reads.iter().chain(&descriptor.writes) {
            let kind = registry
                .descriptor(&declaration.id)
                .expect("typed declarations were validated")
                .kind();
            self.schema_kinds.insert(declaration.id.clone(), kind);
        }
        for schema in writes {
            self.producers
                .entry(schema)
                .or_default()
                .insert(descriptor.id.clone());
        }
        self.rules
            .insert(descriptor.id.clone(), RegisteredRule { descriptor, rule });
        Ok(())
    }

    #[must_use]
    pub(crate) fn descriptor(&self, rule: &PassId) -> Option<&RuleDescriptor> {
        self.rules
            .get(rule)
            .map(|registered| &registered.descriptor)
    }

    pub(crate) fn schedule(&self) -> Result<Vec<PassId>, RuleScheduleError> {
        let graph = self.dependency_graph()?;
        let mut indegree = self
            .rules
            .keys()
            .cloned()
            .map(|rule| (rule, 0usize))
            .collect::<BTreeMap<_, _>>();
        for edges in graph.values() {
            for consumer in edges.keys() {
                *indegree
                    .get_mut(consumer)
                    .expect("rule graph only contains registered rules") += 1;
            }
        }
        let mut ready = indegree
            .iter()
            .filter_map(|(rule, degree)| (*degree == 0).then_some(rule.clone()))
            .collect::<BTreeSet<_>>();
        let mut order = Vec::with_capacity(self.rules.len());
        while let Some(rule) = ready.pop_first() {
            order.push(rule.clone());
            if let Some(edges) = graph.get(&rule) {
                for consumer in edges.keys() {
                    let degree = indegree
                        .get_mut(consumer)
                        .expect("rule graph only contains registered rules");
                    *degree -= 1;
                    if *degree == 0 {
                        ready.insert(consumer.clone());
                    }
                }
            }
        }
        if order.len() != self.rules.len() {
            let (rules, schemas) = find_rule_cycle(&graph)
                .expect("an incomplete evaluation order must contain a cycle");
            return Err(RuleScheduleError::Cycle { rules, schemas });
        }
        Ok(order)
    }

    /// Runs one stable rule order, committing only successful isolated deltas.
    pub(crate) fn run_all<'a>(
        &self,
        services: &C,
        root: &'a EvaluationRoot,
        artifact: ArtifactDbView<'a>,
        committed: &mut EvaluationDb,
    ) -> Result<(), EvaluationPipelineError> {
        let workspace = WorkspaceFactView::compose([(root.entity.scope().clone(), artifact)])
            .map_err(|error| EvaluationPipelineError::WorkspaceContext {
                reason: error.to_string(),
            })?;
        let composition_registry = CompositionRelationRegistry::new();
        let composition = CompositionRelationBuilder::new(root, &workspace, &composition_registry)
            .map_err(|error| EvaluationPipelineError::WorkspaceContext {
                reason: error.to_string(),
            })?
            .finalize()
            .map_err(|error| EvaluationPipelineError::WorkspaceContext {
                reason: error.to_string(),
            })?;
        let evaluation =
            WorkspaceEvaluationView::open(root, &workspace, &composition).map_err(|error| {
                EvaluationPipelineError::WorkspaceContext {
                    reason: error.to_string(),
                }
            })?;
        self.run_all_workspace(services, root, &evaluation, committed)
    }

    /// Runs rules against one authoritative non-flattened workspace context.
    pub(crate) fn run_all_workspace<'a>(
        &self,
        services: &C,
        root: &EvaluationRoot,
        evaluation: &'a WorkspaceEvaluationView<'a>,
        committed: &mut EvaluationDb,
    ) -> Result<(), EvaluationPipelineError> {
        if evaluation.root() != root {
            return Err(EvaluationPipelineError::RootContextMismatch {
                expected: Box::new(root.clone()),
                found: Box::new(evaluation.root().clone()),
            });
        }
        if let Some(found) = committed.incompatible_root(root) {
            return Err(EvaluationPipelineError::RootContextMismatch {
                expected: Box::new(root.clone()),
                found: Box::new(found),
            });
        }
        let artifact = evaluation
            .facts()
            .artifact(root.entity.scope())
            .map_err(|error| EvaluationPipelineError::WorkspaceContext {
                reason: error.to_string(),
            })?;
        let lookup = WorkspaceLookup::new(evaluation.facts(), evaluation.graph());
        lookup.validate_entity(&root.entity).map_err(|reason| {
            EvaluationPipelineError::InvalidRoot {
                root: root.entity.clone(),
                reason,
            }
        })?;
        let order = self.schedule().map_err(EvaluationPipelineError::Schedule)?;
        for rule_id in &order {
            let registered = self
                .rules
                .get(rule_id)
                .expect("scheduled rules remain registered");
            if let Some(declaration) = registered.descriptor.reads.iter().find(|declaration| {
                let Some(kind) = self.schema_kinds.get(&declaration.id).copied() else {
                    return true;
                };
                !matches!(kind, TableKind::Derived | TableKind::Issue)
                    && !(declaration.artifact_available)(evaluation.facts(), kind)
            }) {
                return Err(EvaluationPipelineError::Run(RuleRunError {
                    rule: rule_id.clone(),
                    source: RuleError::MissingArtifactInput {
                        rule: rule_id.clone(),
                        schema: declaration.id.clone(),
                    },
                }));
            }
        }
        let cx = EvaluationCx::new(root, services);
        for rule_id in order {
            let registered = self
                .rules
                .get(&rule_id)
                .expect("scheduled rules remain registered");
            let declared_reads = registered
                .descriptor
                .reads()
                .cloned()
                .collect::<BTreeSet<_>>();
            let declared_writes = registered
                .descriptor
                .writes()
                .cloned()
                .collect::<BTreeSet<_>>();
            let mut delta = EvaluationDb::new();
            {
                let input = EvaluationInput::new(
                    &rule_id,
                    &declared_reads,
                    artifact,
                    evaluation.facts(),
                    committed,
                    artifact.registry(),
                );
                let mut output = EvaluationOutput::new(
                    &rule_id,
                    root,
                    &declared_writes,
                    &mut delta,
                    artifact.registry(),
                    &lookup,
                );
                registered
                    .rule
                    .evaluate(&cx, &input, &mut output)
                    .map_err(|source| {
                        EvaluationPipelineError::Run(RuleRunError {
                            rule: rule_id.clone(),
                            source,
                        })
                    })?;
            }
            committed
                .merge(delta)
                .map_err(|source| EvaluationPipelineError::Commit {
                    rule: rule_id,
                    source,
                })?;
        }
        Ok(())
    }

    fn dependency_graph(&self) -> Result<RuleDependencyGraph, RuleScheduleError> {
        let mut graph = self
            .rules
            .keys()
            .cloned()
            .map(|rule| (rule, BTreeMap::new()))
            .collect::<RuleDependencyGraph>();
        for registered in self.rules.values() {
            for schema in registered.descriptor.reads() {
                if let Some(producers) = self.producers.get(schema) {
                    for producer in producers {
                        graph
                            .get_mut(producer)
                            .expect("every evaluation producer is a registered rule")
                            .entry(registered.descriptor.id.clone())
                            .or_insert_with(BTreeSet::new)
                            .insert(schema.clone());
                    }
                } else if matches!(
                    self.schema_kinds.get(schema),
                    Some(TableKind::Derived | TableKind::Issue)
                ) {
                    return Err(RuleScheduleError::MissingInput {
                        rule: registered.descriptor.id.clone(),
                        schema: schema.clone(),
                    });
                }
            }
        }
        Ok(graph)
    }
}

fn validate_declarations(
    registry: &SchemaRegistry,
    rule: &PassId,
    declarations: &[SchemaDeclaration],
) -> Result<BTreeSet<SchemaId>, RuleRegistrationError> {
    let mut ids = BTreeSet::new();
    for declaration in declarations {
        let access = declaration.access();
        (declaration.validate)(registry).map_err(|reason| {
            RuleRegistrationError::InvalidDeclaration {
                rule: rule.clone(),
                schema: declaration.id.clone(),
                access,
                rust_type: declaration.rust_type,
                reason,
            }
        })?;
        if !ids.insert(declaration.id.clone()) {
            return Err(match access {
                RuleSchemaAccess::Read => RuleRegistrationError::DuplicateRead {
                    rule: rule.clone(),
                    schema: declaration.id.clone(),
                },
                RuleSchemaAccess::WriteDerived | RuleSchemaAccess::WriteIssue => {
                    RuleRegistrationError::DuplicateWrite {
                        rule: rule.clone(),
                        schema: declaration.id.clone(),
                    }
                }
            });
        }
    }
    Ok(ids)
}

type RuleDependencyGraph = BTreeMap<PassId, BTreeMap<PassId, BTreeSet<SchemaId>>>;

fn find_rule_cycle(graph: &RuleDependencyGraph) -> Option<(Vec<PassId>, Vec<SchemaId>)> {
    fn visit(
        rule: &PassId,
        graph: &RuleDependencyGraph,
        states: &mut BTreeMap<PassId, RuleVisitState>,
        stack: &mut Vec<PassId>,
    ) -> Option<(Vec<PassId>, Vec<SchemaId>)> {
        states.insert(rule.clone(), RuleVisitState::Active);
        stack.push(rule.clone());
        for next in graph.get(rule).into_iter().flat_map(|edges| edges.keys()) {
            match states
                .get(next)
                .copied()
                .unwrap_or(RuleVisitState::Unvisited)
            {
                RuleVisitState::Unvisited => {
                    if let Some(cycle) = visit(next, graph, states, stack) {
                        return Some(cycle);
                    }
                }
                RuleVisitState::Active => {
                    let start = stack
                        .iter()
                        .position(|active| active == next)
                        .expect("an active rule remains in the DFS stack");
                    let rules = stack[start..].to_vec();
                    let mut schemas = BTreeSet::new();
                    for edge in rules.windows(2) {
                        schemas.extend(graph[&edge[0]][&edge[1]].iter().cloned());
                    }
                    schemas.extend(
                        graph[rules.last().expect("cycle is nonempty")][next]
                            .iter()
                            .cloned(),
                    );
                    return Some((rules, schemas.into_iter().collect()));
                }
                RuleVisitState::Finished => {}
            }
        }
        stack.pop();
        states.insert(rule.clone(), RuleVisitState::Finished);
        None
    }

    let mut states = BTreeMap::new();
    let mut stack = Vec::new();
    for rule in graph.keys() {
        if states
            .get(rule)
            .copied()
            .unwrap_or(RuleVisitState::Unvisited)
            == RuleVisitState::Unvisited
            && let Some(cycle) = visit(rule, graph, &mut states, &mut stack)
        {
            return Some(cycle);
        }
    }
    None
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RuleVisitState {
    Unvisited,
    Active,
    Finished,
}
