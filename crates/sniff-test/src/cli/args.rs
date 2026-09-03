//! User-facing CLI parsing for the Cargo frontend and direct driver.
use std::path::PathBuf;

use crate::artifact_cache::default_cache_dir;
use crate::config::{DEFAULT_MANIFEST_FILE, OverflowChecks};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

pub(crate) const MANIFEST_PATH_ENV: &str = "SNIFF_TEST_MANIFEST";

#[derive(Debug, Args)]
struct CommonCliArgs {
    /// Path to sniff-test.toml.
    #[arg(long, value_name = "PATH")]
    manifest: Option<PathBuf>,

    /// Analysis cache directory.
    #[arg(long, value_name = "DIR")]
    cache_dir: Option<PathBuf>,

    /// Diagnostic color mode.
    #[arg(long, value_enum, default_value = "auto")]
    color: ColorChoice,

    /// Diagnostic output format.
    #[arg(long, value_enum, default_value = "human")]
    message_format: MessageFormat,
}

impl CommonCliArgs {
    fn into_sniff_test_args(self) -> SniffTestArgs {
        SniffTestArgs {
            manifest_path: self.manifest,
            cache_dir: self.cache_dir,
            color: self.color,
            message_format: self.message_format,
            ..SniffTestArgs::default()
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "cargo-sniff-test",
    bin_name = "cargo sniff-test",
    version,
    about = "Check panic and safety effect contracts through Cargo",
    args_conflicts_with_subcommands = true,
    after_help = "Cargo arguments after `--` are passed to `cargo check`."
)]
pub(super) struct FrontendCli {
    #[command(flatten)]
    common: CommonCliArgs,

    /// Override overflow-check behavior.
    #[arg(long, value_enum, value_name = "MODE")]
    overflow_checks: Option<OverflowChecks>,

    /// Rebuild the standard library with Cargo's build-std support.
    #[arg(long)]
    build_std: bool,

    /// Analyze debug-profile MIR instead of the default release profile.
    #[arg(long)]
    debug: bool,

    #[command(subcommand)]
    command: Option<FrontendCommand>,

    /// Arguments passed to cargo check.
    #[arg(last = true, value_name = "CARGO-ARGS")]
    cargo_args: Vec<String>,
}

#[derive(Debug, Subcommand)]
enum FrontendCommand {
    /// Write a sample sniff-test.toml.
    Init(InitCliArgs),
}

#[derive(Debug, Args)]
pub(super) struct InitCliArgs {
    /// Path to the configuration file to create.
    #[arg(long, default_value = DEFAULT_MANIFEST_FILE, value_name = "PATH")]
    pub(super) manifest: PathBuf,

    /// Overwrite an existing file.
    #[arg(long)]
    pub(super) force: bool,
}

pub(super) enum FrontendAction {
    Run(SniffTestArgs),
    Init(InitCliArgs),
}

impl FrontendCli {
    pub(super) fn try_parse_env() -> Result<Self, clap::Error> {
        let mut args = std::env::args().collect::<Vec<_>>();
        if args.get(1).is_some_and(|arg| arg == "sniff-test") {
            args.remove(1);
        }
        Self::try_parse_from(args)
    }

    pub(super) fn into_action(self) -> FrontendAction {
        if let Some(FrontendCommand::Init(args)) = self.command {
            return FrontendAction::Init(args);
        }

        let mut args = self.common.into_sniff_test_args();
        args.overflow_checks = self.overflow_checks;
        args.build_std = self.build_std;
        let cargo_profile_is_explicit = self
            .cargo_args
            .iter()
            .any(|arg| arg == "--profile" || arg.starts_with("--profile="));
        args.release = !self.debug && !cargo_profile_is_explicit;
        args.cargo_args = self.cargo_args;
        FrontendAction::Run(args)
    }
}

/// Human-facing direct-driver arguments. Cargo wrapper mode bypasses this
/// parser because Cargo owns that invocation protocol.
#[derive(Debug, Parser)]
#[command(
    name = "sniff-test-driver",
    version,
    about = "Run sniff-test directly with rustc arguments",
    after_help = "Rustc arguments must follow `--`. Direct mode follows rustc's exit status; use `cargo sniff-test` to fail the Cargo run on denied findings."
)]
pub(super) struct DriverCli {
    #[command(flatten)]
    common: CommonCliArgs,

    /// Cache artifact facts silently instead of interpreting this unit as a report-producing root.
    #[arg(long)]
    dependency: bool,

    /// Arguments passed directly to rustc.
    #[arg(last = true, required = true, num_args = 1.., value_name = "RUSTC-ARGS")]
    rustc_args: Vec<String>,
}

impl DriverCli {
    pub(super) fn into_parts(self, binary: String) -> (Vec<String>, SniffTestArgs) {
        let mut rustc_args = Vec::with_capacity(self.rustc_args.len() + 1);
        rustc_args.push(binary);
        rustc_args.extend(self.rustc_args);
        let mut args = self.common.into_sniff_test_args();
        args.direct_scope = if self.dependency {
            CrateOutputScope::Dependency
        } else {
            CrateOutputScope::Workspace
        };
        (rustc_args, args)
    }
}

/// Internal rustc-unit classification. This is deliberately not serialized:
/// every public report is a workspace report.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrateOutputScope {
    #[default]
    Workspace,
    Dependency,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SniffTestArgs {
    pub(crate) manifest_path: Option<PathBuf>,
    pub(crate) cache_dir: Option<PathBuf>,
    pub(crate) color: ColorChoice,
    pub(crate) message_format: MessageFormat,
    pub(crate) overflow_checks: Option<OverflowChecks>,
    pub(crate) build_std: bool,
    pub(crate) release: bool,
    pub(crate) cargo_args: Vec<String>,
    /// Workspace member manifests from `cargo metadata`, plumbed to the
    /// driver so crate scope uses real membership instead of path prefixes.
    /// Empty in direct driver mode.
    pub(crate) workspace_manifests: Vec<PathBuf>,
    /// True when the driver runs as cargo's `RUSTC_WRAPPER`; set by the
    /// driver itself, never carried through the environment.
    #[serde(skip)]
    pub(crate) under_cargo: bool,
    /// Explicit artifact scope for standalone driver invocations.
    #[serde(skip)]
    pub(crate) direct_scope: CrateOutputScope,
}

impl SniffTestArgs {
    pub(crate) fn manifest_path(&self) -> PathBuf {
        self.manifest_path
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_MANIFEST_FILE))
    }

    pub(crate) fn cache_dir(&self) -> PathBuf {
        self.cache_dir
            .clone()
            .unwrap_or_else(|| default_cache_dir("target"))
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ColorChoice {
    #[default]
    Auto,
    Always,
    Never,
}

impl ColorChoice {
    #[must_use]
    pub(crate) fn as_cargo_arg(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum MessageFormat {
    #[default]
    Human,
    Json,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser as _;

    use super::{CrateOutputScope, DriverCli, FrontendAction, FrontendCli, MessageFormat};

    #[test]
    fn frontend_parses_equals_options_and_cargo_args_after_separator() {
        let cli = FrontendCli::try_parse_from([
            "cargo-sniff-test",
            "--message-format=json",
            "--",
            "--locked",
        ])
        .expect("frontend arguments should parse");

        let FrontendAction::Run(args) = cli.into_action() else {
            panic!("expected frontend run action");
        };
        assert_eq!(args.message_format, MessageFormat::Json);
        assert_eq!(args.cargo_args, ["--locked"]);
    }

    #[test]
    fn frontend_selects_profile_from_arguments() {
        for (argv, expected_release) in [
            (&["cargo-sniff-test"][..], true),
            (&["cargo-sniff-test", "--debug"][..], false),
            (&["cargo-sniff-test", "--", "--profile", "ci"][..], false),
            (&["cargo-sniff-test", "--", "--profile=ci"][..], false),
        ] {
            let cli = FrontendCli::try_parse_from(argv).expect("frontend arguments should parse");

            let FrontendAction::Run(args) = cli.into_action() else {
                panic!("expected frontend run action");
            };
            assert_eq!(args.release, expected_release, "argv: {argv:?}");
        }
    }

    #[test]
    fn frontend_rejects_unknown_arguments() {
        let error = FrontendCli::try_parse_from(["cargo-sniff-test", "--not-an-option"])
            .expect_err("unknown arguments should be rejected");

        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn frontend_parses_init_subcommand() {
        let cli = FrontendCli::try_parse_from([
            "cargo-sniff-test",
            "init",
            "--manifest",
            "policy.toml",
            "--force",
        ])
        .expect("init arguments should parse");

        let FrontendAction::Init(args) = cli.into_action() else {
            panic!("expected init action");
        };
        assert_eq!(args.manifest, PathBuf::from("policy.toml"));
        assert!(args.force);
    }

    #[test]
    fn direct_driver_parses_options_before_rustc_args() {
        let cli = DriverCli::try_parse_from(
            [
                "sniff-test-driver",
                "--message-format=json",
                "--dependency",
                "--",
                "--crate-name",
                "demo",
            ]
            .map(String::from),
        )
        .expect("direct driver arguments should parse");
        let (rustc_args, args) = cli.into_parts(String::from("sniff-test-driver"));

        assert_eq!(args.message_format, MessageFormat::Json);
        assert_eq!(args.direct_scope, CrateOutputScope::Dependency);
        assert_eq!(rustc_args, ["sniff-test-driver", "--crate-name", "demo"]);
    }
}
