//! Human evidence selectors and root-derived attachment schema.
//!
//! Permanent marker claim entities remain artifact-owned by the collection
//! schema pack. This module owns only their selector vocabulary and the exact
//! root-witness attachments consumed by evaluation packs.

use serde::{Deserialize, Serialize};

use super::evaluation::RelationTrace;
use super::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use super::schema::{DerivedSchema, RowSchema};
use super::workspace::{ScopedEntityId, ScopedEntityRef, ScopedRowRef};

pub(crate) mod markers;

use markers::MarkerClaimEntity;

/// How a human evidence claim selects requirements in one semantic group.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum EvidenceClaimSelector {
    /// An unnamed claim applies to every requirement in its attached group.
    Unnamed,
    /// A human requirement name resolved by the domain evidence producer.
    Named(String),
    /// Explicit source-level references resolved by the domain evidence producer.
    Explicit(Vec<String>),
}

/// Root-preparation result applying one claim to one obligation witness.
///
/// The source, endpoint, semantic group, complete scoped trace, and root
/// traversal order form the witness identity. The explicit order distinguishes
/// two visits whose structural trace is identical but whose propagated marker
/// state differs. Keeping this identity prevents evidence carried along one
/// route from discharging the same endpoint reached through a different,
/// unmarked route. A root traversal expands a lexical or propagated claim into
/// one attachment for every obligation witness to which it applies.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct EvidenceAttachment {
    claim: ScopedEntityRef,
    obligation_source: ScopedRowRef,
    endpoint: ScopedEntityRef,
    group: ScopedEntityRef,
    trace: RelationTrace,
    witness_order: u64,
    resolved_requirements: Vec<ScopedRowRef>,
}

impl RowSchema for EvidenceAttachment {
    const ID: &'static str = "sniff-test.human.evidence-attachment";
    const VERSION: u32 = 4;
}

impl DerivedSchema for EvidenceAttachment {}

impl EvidenceAttachment {
    #[must_use]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the constructor consumes the typed identity at the erasure boundary"
    )]
    pub(crate) fn new(
        claim: ScopedEntityId<MarkerClaimEntity>,
        obligation_source: ScopedRowRef,
        endpoint: ScopedEntityRef,
        group: ScopedEntityRef,
        trace: RelationTrace,
        witness_order: u64,
        mut resolved_requirements: Vec<ScopedRowRef>,
    ) -> Self {
        resolved_requirements.sort();
        resolved_requirements.dedup();
        Self {
            claim: claim.erase(),
            obligation_source,
            endpoint,
            group,
            trace,
            witness_order,
            resolved_requirements,
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn new_for_test(
        claim: ScopedEntityRef,
        obligation_source: ScopedRowRef,
        endpoint: ScopedEntityRef,
        group: ScopedEntityRef,
        trace: RelationTrace,
        witness_order: u64,
        mut resolved_requirements: Vec<ScopedRowRef>,
    ) -> Self {
        resolved_requirements.sort();
        resolved_requirements.dedup();
        Self {
            claim,
            obligation_source,
            endpoint,
            group,
            trace,
            witness_order,
            resolved_requirements,
        }
    }

    #[must_use]
    pub(crate) const fn claim(&self) -> &ScopedEntityRef {
        &self.claim
    }

    #[must_use]
    pub(crate) const fn obligation_source(&self) -> &ScopedRowRef {
        &self.obligation_source
    }

    #[must_use]
    pub(crate) const fn endpoint(&self) -> &ScopedEntityRef {
        &self.endpoint
    }

    #[must_use]
    pub(crate) const fn group(&self) -> &ScopedEntityRef {
        &self.group
    }

    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }

    #[must_use]
    pub(crate) const fn witness_order(&self) -> u64 {
        self.witness_order
    }

    #[must_use]
    pub(crate) fn resolved_requirements(&self) -> &[ScopedRowRef] {
        &self.resolved_requirements
    }
}

/// Installs root-derived evidence attachments independently of any domain pack.
pub(crate) struct HumanEvidencePack;

impl<C: ?Sized> AnalysisPack<C> for HumanEvidencePack {
    fn register(&self, registry: &mut AnalysisRegistry<C>) -> Result<(), PackRegistrationError> {
        registry.register_derived::<EvidenceAttachment>()?;
        Ok(())
    }
}
