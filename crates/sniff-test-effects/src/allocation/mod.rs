use sniff_test_core::artifact::EffectKind;
use sniff_test_core::config::{EffectConfig, LintLevel};
use sniff_test_core::effects::EffectSpec;
use sniff_test_core::effects::visit::EffectPassRegistry;

use self::visit::AllocationInvocationPass;

pub mod visit;

pub struct Allocation;

pub enum AllocationOperation {
    HeapAllocation,
}

impl AllocationOperation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::HeapAllocation => "heap-allocation",
        }
    }
}

impl From<AllocationOperation> for EffectKind {
    fn from(operation: AllocationOperation) -> Self {
        Self::new(operation.as_str())
    }
}

impl EffectSpec for Allocation {
    const EFFECT_NAME: &'static str = "allocation";
    const OBLIGATION: &'static str = "Allocations";
    const JUSTIFICATION: &'static str = "ALLOCATION";

    fn default_config() -> EffectConfig {
        EffectConfig::builder()
            .operation(
                AllocationOperation::HeapAllocation.as_str(),
                LintLevel::Warn,
            )
            .build()
    }

    fn register_passes(registry: &mut EffectPassRegistry) {
        registry.register_mir_pass::<Self>(Box::new(AllocationInvocationPass));
    }
}
