//! Presentation owned by the panic pack.
//!
//! The renderer formats an already-evaluated issue. Root naming, lint policy,
//! verified source-anchor resolution, and rustc emission remain responsibilities
//! of the CLI adapter and generic rendering infrastructure.

use serde_json::{Value, json};

use super::model::{MirAssertKind, UnsatisfiedCompilerAssertIssue};
use crate::analysis::facts::render::{IssueRenderer, RenderCx, RenderedDiagnostic};
use crate::panics::CompilerAssertKind;

const GENERAL_PANIC_HELP: &str = "add a guard, document the panic with `# Panics`, or add `// PANIC:` if a local invariant proves it cannot panic";
const COMPILER_ASSERT_REASON: &str = "compiler assert";

/// Stable public presentation derived from one precise compiler assertion.
///
/// Keeping these fields together gives both the generic renderer and the CLI
/// projection one pack-owned semantic boundary. In particular, callers never
/// need to recover typed values by parsing [`RenderedDiagnostic::data`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompilerAssertPresentation {
    public_kind: CompilerAssertKind,
    description: &'static str,
    reason: &'static str,
    target: String,
    message: String,
    effect_note: String,
    help: &'static str,
}

impl CompilerAssertPresentation {
    #[must_use]
    pub(crate) const fn public_kind(&self) -> CompilerAssertKind {
        self.public_kind
    }

    #[must_use]
    pub(crate) const fn description(&self) -> &'static str {
        self.description
    }

    #[must_use]
    pub(crate) const fn reason(&self) -> &'static str {
        self.reason
    }

    #[must_use]
    pub(crate) fn target(&self) -> &str {
        &self.target
    }

    #[must_use]
    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub(crate) fn effect_note(&self) -> &str {
        &self.effect_note
    }

    #[must_use]
    pub(crate) const fn help(&self) -> &'static str {
        self.help
    }
}

/// Builds the pack-owned public presentation for a precise MIR assertion.
#[must_use]
pub(crate) fn compiler_assert_presentation(kind: MirAssertKind) -> CompilerAssertPresentation {
    let public_kind = super::coarse_public_assert_kind(kind);
    let description = kind.human_description();
    CompilerAssertPresentation {
        public_kind,
        description,
        reason: COMPILER_ASSERT_REASON,
        target: format!("compiler assert {description}"),
        message: format!("compiler assertion may panic: {description}"),
        effect_note: format!("panic may happen here: compiler assertion: {description}"),
        help: GENERAL_PANIC_HELP,
    }
}

pub(super) struct UnsatisfiedCompilerAssertRenderer;

impl IssueRenderer<UnsatisfiedCompilerAssertIssue> for UnsatisfiedCompilerAssertRenderer {
    fn render(
        &self,
        issue: &UnsatisfiedCompilerAssertIssue,
        _cx: &RenderCx<'_>,
    ) -> RenderedDiagnostic {
        let presentation = compiler_assert_presentation(issue.kind());
        let mut diagnostic = RenderedDiagnostic::new(presentation.message());
        diagnostic.notes.push(presentation.effect_note().to_owned());
        diagnostic.help.push(presentation.help().to_owned());

        let public_kind = presentation.public_kind();
        let public_kind_data = json!(public_kind);
        let Value::String(public_kind_name) = &public_kind_data else {
            unreachable!("fieldless CompilerAssertKind must serialize as a JSON string");
        };
        let public_kind_order = public_assert_kind_order(public_kind);
        diagnostic.data = json!({
            "kind": "compiler-assert",
            "compiler-assert-kind": public_kind_data,
            "reason": presentation.reason(),
            "target": presentation.target(),
        });
        diagnostic.sort_key.extend([
            format!("{public_kind_order:02}"),
            public_kind_name.clone(),
            presentation.description().to_owned(),
        ]);
        diagnostic
    }
}

/// Collapses the pack's precise MIR subtype only at the public report-v13
/// compatibility boundary. Binary operation detail remains authoritative in
/// [`MirAssertKind`] and is not lost from extracted facts or evaluated issues.
pub(crate) const fn coarse_public_assert_kind(kind: MirAssertKind) -> CompilerAssertKind {
    match kind {
        MirAssertKind::BoundsCheck => CompilerAssertKind::BoundsCheck,
        MirAssertKind::Overflow(_) | MirAssertKind::OpaqueOverflow => CompilerAssertKind::Overflow,
        MirAssertKind::OverflowNegation => CompilerAssertKind::OverflowNegation,
        MirAssertKind::DivisionByZero => CompilerAssertKind::DivisionByZero,
        MirAssertKind::RemainderByZero => CompilerAssertKind::RemainderByZero,
        MirAssertKind::ResumedAfterReturn => CompilerAssertKind::ResumedAfterReturn,
        MirAssertKind::ResumedAfterPanic => CompilerAssertKind::ResumedAfterPanic,
        MirAssertKind::ResumedAfterDrop => CompilerAssertKind::ResumedAfterDrop,
        MirAssertKind::MisalignedPointerDereference => {
            CompilerAssertKind::MisalignedPointerDereference
        }
        MirAssertKind::NullPointerDereference => CompilerAssertKind::NullPointerDereference,
        MirAssertKind::InvalidEnumConstruction => CompilerAssertKind::InvalidEnumConstruction,
    }
}

/// Preserves the declaration order used by the legacy finding comparator.
const fn public_assert_kind_order(kind: CompilerAssertKind) -> u8 {
    match kind {
        CompilerAssertKind::BoundsCheck => 0,
        CompilerAssertKind::Overflow => 1,
        CompilerAssertKind::OverflowNegation => 2,
        CompilerAssertKind::DivisionByZero => 3,
        CompilerAssertKind::RemainderByZero => 4,
        CompilerAssertKind::ResumedAfterReturn => 5,
        CompilerAssertKind::ResumedAfterPanic => 6,
        CompilerAssertKind::ResumedAfterDrop => 7,
        CompilerAssertKind::MisalignedPointerDereference => 8,
        CompilerAssertKind::NullPointerDereference => 9,
        CompilerAssertKind::InvalidEnumConstruction => 10,
    }
}
