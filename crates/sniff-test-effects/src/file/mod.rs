use sniff_test_core::artifact::EffectKind;
use sniff_test_core::config::{EffectConfig, LintLevel};
use sniff_test_core::effects::EffectSpec;
use sniff_test_core::effects::visit::EffectPassRegistry;

use self::visit::FileMutationPass;

pub mod visit;

pub struct File;

#[derive(Clone, Copy)]
pub enum FileOperation {
    Write,
    Create,
    Truncate,
    Delete,
}

impl FileOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Create => "create",
            Self::Truncate => "truncate",
            Self::Delete => "delete",
        }
    }
}

impl From<FileOperation> for EffectKind {
    fn from(operation: FileOperation) -> Self {
        Self::new(operation.as_str())
    }
}

impl EffectSpec for File {
    const EFFECT_NAME: &'static str = "file";
    const OBLIGATION: &'static str = "File";
    const JUSTIFICATION: &'static str = "FILE";

    fn default_config() -> EffectConfig {
        EffectConfig::builder()
            .operations(
                LintLevel::Warn,
                [
                    FileOperation::Write,
                    FileOperation::Create,
                    FileOperation::Truncate,
                    FileOperation::Delete,
                ]
                .map(FileOperation::as_str),
            )
            .build()
    }

    fn register_passes(registry: &mut EffectPassRegistry) {
        registry.register_mir_pass::<Self>(Box::new(FileMutationPass));
    }
}
