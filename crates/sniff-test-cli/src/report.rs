//! Panic report rendering.
use owo_colors::Style;
use reachability::{ReachabilityEdge, ReachabilityEdgeId, ReachabilityGraph, ReachabilityNodeKind};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use rustc_span::Pos;
use sniff_test::cache::CachedFunctionSummary;
use sniff_test::namespace::canonical_namespace;
use sniff_test::panics::{PanicEvidence, PanicEvidenceKind, trace_edges_until, trigger_edge_id};

use crate::PanicFindingCounts;

#[derive(Debug, Clone, Copy)]
pub(crate) struct PanicReportOutput<'output> {
    pub(crate) crate_name: &'output str,
    pub(crate) color: bool,
}

#[derive(Debug)]
pub(crate) struct PanicReport {
    root: String,
    root_declaration: Option<String>,
    include_stack: bool,
    groups: Vec<PanicReportGroup>,
}

impl PanicReport {
    pub(crate) fn new(root: String, root_declaration: Option<String>, include_stack: bool) -> Self {
        Self {
            root,
            root_declaration,
            include_stack,
            groups: Vec::new(),
        }
    }

    pub(crate) fn push_panic_evidence<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        graph: &ReachabilityGraph<'tcx>,
        evidence: &PanicEvidence,
    ) {
        let trigger_edge_id = trigger_edge_id(graph, evidence);
        let trigger_edge = graph.edge(trigger_edge_id);
        let kind = ReportDetailKind::from_evidence(&evidence.kind);
        let detail = PanicReportDetail {
            kind,
            reason: report_evidence_kind(tcx, &evidence.kind),
            stack: self
                .include_stack
                .then(|| render_trace(tcx, graph, &evidence.trace.edge_ids)),
        };
        self.push_detail(
            render_span(tcx, trigger_edge.span),
            Some(render_edge_without_span(tcx, graph, trigger_edge)),
            detail,
        );
    }

    pub(crate) fn push_panic_obligation<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        graph: &ReachabilityGraph<'tcx>,
        evidence: &PanicEvidence,
        obligation_edge_id: Option<ReachabilityEdgeId>,
        documented_def_id: DefId,
        kind: ReportDetailKind,
    ) {
        let documented = canonical_namespace(tcx, documented_def_id);
        let (span, edge) = obligation_edge_id.map_or_else(
            || {
                (
                    render_span(tcx, tcx.def_span(documented_def_id)),
                    Some(String::from("report root documents panic behavior")),
                )
            },
            |edge_id| {
                let edge = graph.edge(edge_id);
                (
                    render_span(tcx, edge.span),
                    Some(render_edge_without_span(tcx, graph, edge)),
                )
            },
        );
        let stack_edges = self
            .include_stack
            .then(|| trace_edges_until(evidence, obligation_edge_id));
        let detail = PanicReportDetail {
            kind,
            reason: ReportText::from_segments([
                ReportTextSegment::styled(OutputStyle::Info, documented),
                ReportTextSegment::plain(" is documented panicable"),
            ]),
            stack: stack_edges.map(|edges| render_trace(tcx, graph, &edges)),
        };
        self.push_detail(span, edge, detail);
    }

    pub(crate) fn push_cached_dependency_panic<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        graph: &ReachabilityGraph<'tcx>,
        edge_id: ReachabilityEdgeId,
        summary: &CachedFunctionSummary,
    ) {
        let edge = graph.edge(edge_id);
        self.push_detail(
            render_span(tcx, edge.span),
            Some(render_edge_without_span(tcx, graph, edge)),
            PanicReportDetail {
                kind: ReportDetailKind::CachedDependencyPanic,
                reason: cached_dependency_panic_reason(summary),
                stack: None,
            },
        );
    }

    pub(crate) fn push_cached_dependency_obligation<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        graph: &ReachabilityGraph<'tcx>,
        edge_id: ReachabilityEdgeId,
        summary: &CachedFunctionSummary,
        kind: ReportDetailKind,
    ) {
        let edge = graph.edge(edge_id);
        self.push_detail(
            render_span(tcx, edge.span),
            Some(render_edge_without_span(tcx, graph, edge)),
            PanicReportDetail {
                kind,
                reason: ReportText::from_segments([
                    ReportTextSegment::styled(OutputStyle::Info, summary.path.clone()),
                    ReportTextSegment::plain(" is cached panicable"),
                ]),
                stack: None,
            },
        );
    }

    fn push_detail(&mut self, span: String, edge: Option<String>, detail: PanicReportDetail) {
        if let Some(group) = self
            .groups
            .iter_mut()
            .find(|group| group.span == span && group.edge == edge)
        {
            group.push(detail);
        } else {
            let mut group = PanicReportGroup {
                span,
                edge,
                counts: ReportCounts::default(),
                details: Vec::new(),
            };
            group.push(detail);
            self.groups.push(group);
        }
    }

    pub(crate) fn emit(&self, crate_name: &str, color: bool) {
        if self.groups.is_empty() {
            return;
        }

        eprintln!(
            "{} {}",
            paint(
                color,
                OutputStyle::Bold,
                &format!("sniff-test[{crate_name}]:")
            ),
            paint(color, OutputStyle::Info, &self.root)
        );
        if let Some(root_declaration) = &self.root_declaration {
            eprintln!(
                "  {} {}",
                paint(color, OutputStyle::Dim, "declared at"),
                paint(color, OutputStyle::Info, root_declaration)
            );
        }

        for group in &self.groups {
            group.emit(color);
        }
    }
}

#[derive(Debug)]
struct PanicReportGroup {
    span: String,
    edge: Option<String>,
    counts: ReportCounts,
    details: Vec<PanicReportDetail>,
}

impl PanicReportGroup {
    fn push(&mut self, detail: PanicReportDetail) {
        self.counts.increment(detail.kind);
        self.details.push(detail);
    }

    fn emit(&self, color: bool) {
        eprintln!(
            "  {} {}",
            paint(color, OutputStyle::Dim, "at"),
            paint(color, OutputStyle::Info, &self.span)
        );
        eprintln!(
            "    {} {}",
            paint(color, OutputStyle::Dim, "counts"),
            self.counts.render(color)
        );
        if let Some(edge) = &self.edge {
            eprintln!(
                "    {} {}",
                paint(color, OutputStyle::Dim, "edge"),
                paint(color, OutputStyle::Info, edge)
            );
        }
        for (reason, count, kind) in self.reason_counts() {
            eprintln!(
                "    {} {} {}",
                paint(color, kind.style(), kind.label()),
                paint(color, OutputStyle::Dim, &format!("x{count}")),
                reason.render(color)
            );
        }

        for (detail_index, detail) in self.details.iter().enumerate() {
            let Some(stack) = &detail.stack else {
                continue;
            };
            eprintln!(
                "    {} {} {}",
                paint(color, OutputStyle::Dim, "stack"),
                paint(color, detail.kind.style(), detail.kind.label()),
                paint(color, OutputStyle::Dim, &format!("#{}", detail_index + 1))
            );
            for (frame_index, frame) in stack.iter().enumerate() {
                eprintln!(
                    "      {} {}",
                    paint(color, OutputStyle::Dim, &format!("{frame_index}:")),
                    paint(color, OutputStyle::Info, frame)
                );
            }
        }
    }

    fn reason_counts(&self) -> Vec<(ReportText, usize, ReportDetailKind)> {
        let mut reasons = Vec::<(ReportText, usize, ReportDetailKind)>::new();
        for detail in &self.details {
            if let Some((_, count, _)) = reasons
                .iter_mut()
                .find(|(reason, _, kind)| *reason == detail.reason && *kind == detail.kind)
            {
                *count += 1;
            } else {
                reasons.push((detail.reason.clone(), 1, detail.kind));
            }
        }
        reasons
    }
}

#[derive(Debug, Default)]
struct ReportCounts {
    asserts: usize,
    panic_invocations: usize,
    cached_dependency_panics: usize,
    panic_obligations: usize,
    trusted_panic_obligations: usize,
}

impl ReportCounts {
    fn increment(&mut self, kind: ReportDetailKind) {
        match kind {
            ReportDetailKind::CompilerAssert => self.asserts += 1,
            ReportDetailKind::PanicInvocation => self.panic_invocations += 1,
            ReportDetailKind::CachedDependencyPanic => self.cached_dependency_panics += 1,
            ReportDetailKind::PanicObligation => self.panic_obligations += 1,
            ReportDetailKind::TrustedPanicObligation => self.trusted_panic_obligations += 1,
        }
    }

    fn render(&self, color: bool) -> String {
        [
            (ReportDetailKind::CompilerAssert, self.asserts),
            (ReportDetailKind::PanicInvocation, self.panic_invocations),
            (
                ReportDetailKind::CachedDependencyPanic,
                self.cached_dependency_panics,
            ),
            (ReportDetailKind::PanicObligation, self.panic_obligations),
            (
                ReportDetailKind::TrustedPanicObligation,
                self.trusted_panic_obligations,
            ),
        ]
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .map(|(kind, count)| {
            count_phrase(color, kind.style(), count, kind.label(), kind.count_label())
        })
        .collect::<Vec<_>>()
        .join(", ")
    }
}

#[derive(Debug)]
struct PanicReportDetail {
    kind: ReportDetailKind,
    reason: ReportText,
    stack: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportText {
    segments: Vec<ReportTextSegment>,
}

impl ReportText {
    fn plain(text: impl Into<String>) -> Self {
        Self::from_segments([ReportTextSegment::plain(text)])
    }

    fn from_segments(segments: impl IntoIterator<Item = ReportTextSegment>) -> Self {
        Self {
            segments: segments.into_iter().collect(),
        }
    }

    fn render(&self, color: bool) -> String {
        self.segments
            .iter()
            .map(|segment| segment.render(color))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportTextSegment {
    style: Option<OutputStyle>,
    text: String,
}

impl ReportTextSegment {
    fn plain(text: impl Into<String>) -> Self {
        Self {
            style: None,
            text: text.into(),
        }
    }

    fn styled(style: OutputStyle, text: impl Into<String>) -> Self {
        Self {
            style: Some(style),
            text: text.into(),
        }
    }

    fn render(&self, color: bool) -> String {
        self.style.map_or_else(
            || self.text.clone(),
            |style| paint(color, style, &self.text),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReportDetailKind {
    CompilerAssert,
    PanicInvocation,
    CachedDependencyPanic,
    PanicObligation,
    TrustedPanicObligation,
}

impl ReportDetailKind {
    fn from_evidence(kind: &PanicEvidenceKind) -> Self {
        match kind {
            PanicEvidenceKind::CompilerAssert => Self::CompilerAssert,
            PanicEvidenceKind::PanicObligation { .. } => Self::PanicObligation,
            PanicEvidenceKind::PanicSink { .. } => Self::PanicInvocation,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::CompilerAssert => "assert",
            Self::PanicInvocation => "panic invocation",
            Self::CachedDependencyPanic => "cached dependency panic",
            Self::PanicObligation => "panic obligation",
            Self::TrustedPanicObligation => "trusted obligation",
        }
    }

    fn count_label(self) -> &'static str {
        match self {
            Self::CompilerAssert => "asserts",
            Self::PanicInvocation => "panic invocations",
            Self::CachedDependencyPanic => "cached dependency panics",
            Self::PanicObligation => "panic obligations",
            Self::TrustedPanicObligation => "trusted obligations",
        }
    }

    fn style(self) -> OutputStyle {
        match self {
            Self::CompilerAssert | Self::PanicInvocation | Self::CachedDependencyPanic => {
                OutputStyle::Risk
            }
            Self::PanicObligation => OutputStyle::Warning,
            Self::TrustedPanicObligation => OutputStyle::Trusted,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputStyle {
    Bold,
    Dim,
    Risk,
    Warning,
    Trusted,
    Info,
}

impl OutputStyle {
    fn style(self) -> Style {
        match self {
            Self::Bold => Style::new().bold(),
            Self::Dim => Style::new().dimmed(),
            Self::Risk => Style::new().red(),
            Self::Warning => Style::new().yellow(),
            Self::Trusted => Style::new().blue(),
            Self::Info => Style::new().cyan(),
        }
    }
}

fn paint(color: bool, style: OutputStyle, text: &str) -> String {
    if color {
        style.style().style(text).to_string()
    } else {
        text.to_owned()
    }
}

fn count_phrase(
    color: bool,
    style: OutputStyle,
    count: usize,
    singular: &str,
    plural: &str,
) -> String {
    paint(color, style, &count_text(count, singular, plural))
}

fn count_text(count: usize, singular: &str, plural: &str) -> String {
    let label = if count == 1 { singular } else { plural };
    format!("{count} {label}")
}

fn dependency_hit_phrase(color: bool, hits: usize, total: usize) -> String {
    let label = if hits == 1 {
        "dependency cache hit"
    } else {
        "dependency cache hits"
    };
    paint(color, OutputStyle::Info, &format!("{hits}/{total} {label}"))
}

pub(crate) fn emit_crate_panic_summary(
    crate_name: &str,
    concrete_roots: usize,
    generic_roots: usize,
    counts: PanicFindingCounts,
    dependency_hits: usize,
    dependency_count: usize,
    color: bool,
) {
    if counts.raw_panic_paths == 0
        && counts.panic_obligations == 0
        && counts.trusted_panic_obligations == 0
    {
        return;
    }

    eprintln!(
        "{} {}, {}, {}, {}, {}, {}",
        paint(
            color,
            OutputStyle::Bold,
            &format!("sniff-test[{crate_name}]:")
        ),
        count_phrase(
            color,
            OutputStyle::Info,
            concrete_roots,
            "concrete panic root",
            "concrete panic roots"
        ),
        count_phrase(
            color,
            OutputStyle::Info,
            generic_roots,
            "generic root",
            "generic roots"
        ),
        count_phrase(
            color,
            OutputStyle::Risk,
            counts.raw_panic_paths,
            "raw panic path",
            "raw panic paths"
        ),
        count_phrase(
            color,
            OutputStyle::Warning,
            counts.panic_obligations,
            "panic obligation",
            "panic obligations"
        ),
        count_phrase(
            color,
            OutputStyle::Trusted,
            counts.trusted_panic_obligations,
            "trusted panic obligation",
            "trusted panic obligations"
        ),
        dependency_hit_phrase(color, dependency_hits, dependency_count),
    );
}

pub(crate) fn emit_dependency_panic_summary(
    crate_name: &str,
    concrete_roots: usize,
    generic_roots: usize,
    counts: PanicFindingCounts,
    dependency_hits: usize,
    dependency_count: usize,
    color: bool,
) {
    if counts.raw_panic_paths == 0
        && counts.panic_obligations == 0
        && counts.trusted_panic_obligations == 0
    {
        return;
    }

    eprintln!(
        "{} {}, {}, {}, {}, {}, {}, {}",
        paint(
            color,
            OutputStyle::Bold,
            &format!("sniff-test[{crate_name}]:")
        ),
        paint(color, OutputStyle::Dim, "analyzed dependency"),
        count_phrase(
            color,
            OutputStyle::Info,
            concrete_roots,
            "concrete panic root",
            "concrete panic roots"
        ),
        count_phrase(
            color,
            OutputStyle::Info,
            generic_roots,
            "generic root",
            "generic roots"
        ),
        count_phrase(
            color,
            OutputStyle::Risk,
            counts.raw_panic_paths,
            "raw panic path",
            "raw panic paths"
        ),
        count_phrase(
            color,
            OutputStyle::Warning,
            counts.panic_obligations,
            "panic obligation",
            "panic obligations"
        ),
        count_phrase(
            color,
            OutputStyle::Trusted,
            counts.trusted_panic_obligations,
            "trusted panic obligation",
            "trusted panic obligations"
        ),
        dependency_hit_phrase(color, dependency_hits, dependency_count),
    );
}

pub(crate) fn emit_missing_report_root(crate_name: &str, root: &str, color: bool) {
    eprintln!(
        "{} {} {}",
        paint(
            color,
            OutputStyle::Bold,
            &format!("sniff-test[{crate_name}]:")
        ),
        paint(color, OutputStyle::Warning, "missing report root"),
        paint(color, OutputStyle::Info, root),
    );
}

pub(crate) fn render_trace<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge_ids: &[ReachabilityEdgeId],
) -> Vec<String> {
    edge_ids
        .iter()
        .map(|edge_id| render_edge(tcx, graph, *edge_id))
        .collect()
}

fn report_evidence_kind(tcx: TyCtxt<'_>, kind: &PanicEvidenceKind) -> ReportText {
    match kind {
        PanicEvidenceKind::CompilerAssert => ReportText::plain("compiler assert"),
        PanicEvidenceKind::PanicObligation { def_id } => ReportText::from_segments([
            ReportTextSegment::styled(OutputStyle::Info, canonical_namespace(tcx, *def_id)),
            ReportTextSegment::plain(" is documented panicable"),
        ]),
        PanicEvidenceKind::PanicSink { def_id } => ReportText::from_segments([
            ReportTextSegment::plain("panic sink "),
            ReportTextSegment::styled(OutputStyle::Info, canonical_namespace(tcx, *def_id)),
        ]),
    }
}

fn cached_dependency_panic_reason(summary: &CachedFunctionSummary) -> ReportText {
    let mut segments = vec![
        ReportTextSegment::styled(OutputStyle::Info, summary.path.clone()),
        ReportTextSegment::plain(" has cached panic evidence: "),
    ];
    let mut has_count = false;

    for (count, style, singular, plural) in [
        (
            summary.raw_panic_paths,
            OutputStyle::Risk,
            "raw panic path",
            "raw panic paths",
        ),
        (
            summary.panic_obligations,
            OutputStyle::Warning,
            "panic obligation",
            "panic obligations",
        ),
        (
            summary.trusted_panic_obligations,
            OutputStyle::Trusted,
            "trusted panic obligation",
            "trusted panic obligations",
        ),
    ] {
        if count == 0 {
            continue;
        }
        if has_count {
            segments.push(ReportTextSegment::plain(", "));
        }
        segments.push(ReportTextSegment::styled(
            style,
            count_text(count, singular, plural),
        ));
        has_count = true;
    }

    if !has_count {
        segments.push(ReportTextSegment::plain("0 raw panic paths"));
    }

    ReportText::from_segments(segments)
}

pub(crate) fn render_edge<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge_id: ReachabilityEdgeId,
) -> String {
    let edge = graph.edge(edge_id);
    format!(
        "{}: {}",
        render_span(tcx, edge.span),
        render_edge_without_span(tcx, graph, edge)
    )
}

pub(crate) fn render_edge_without_span<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge: &ReachabilityEdge,
) -> String {
    format!(
        "{} --{}-> {}",
        render_node(tcx, &graph.node(edge.source).kind),
        edge.kind,
        render_node(tcx, &graph.node(edge.target).kind)
    )
}

pub(crate) fn render_node<'tcx>(tcx: TyCtxt<'tcx>, node: &ReachabilityNodeKind<'tcx>) -> String {
    match node {
        ReachabilityNodeKind::Instance(instance) => canonical_namespace(tcx, instance.def_id()),
        ReachabilityNodeKind::CompilerAssert { message } => format!("compiler assert {message:?}"),
        ReachabilityNodeKind::IndirectCall { callee_ty } => format!("indirect call {callee_ty:?}"),
        ReachabilityNodeKind::DynObjectCast {
            source_ty,
            target_ty,
        } => format!("dyn object cast {source_ty:?} as {target_ty:?}"),
    }
}

pub(crate) fn render_span(tcx: TyCtxt<'_>, span: rustc_span::Span) -> String {
    tcx.sess.source_map().span_to_diagnostic_string(span)
}

pub(crate) fn render_span_start(tcx: TyCtxt<'_>, span: rustc_span::Span) -> String {
    let location = tcx.sess.source_map().lookup_char_pos(span.lo());
    format!(
        "{}:{}:{}",
        location.file.name.prefer_local_unconditionally(),
        location.line,
        location.col.to_usize() + 1
    )
}
