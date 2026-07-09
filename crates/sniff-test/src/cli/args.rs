//! Arg parsing for the cargo frontend cli
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use crate::cache::default_cache_dir;
use crate::config::{DEFAULT_MANIFEST_FILE, OverflowChecks};
use serde::{Deserialize, Serialize};

pub(crate) const MANIFEST_PATH_ENV: &str = "SNIFF_TEST_MANIFEST";

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
    #[serde(default)]
    pub(crate) workspace_manifests: Vec<PathBuf>,
    /// True when the driver runs as cargo's `RUSTC_WRAPPER`; set by the
    /// driver itself, never carried through the environment.
    #[serde(skip)]
    pub(crate) under_cargo: bool,
}

impl SniffTestArgs {
    pub(crate) fn parse_from_env() -> Self {
        let mut args = Self::parse_from_args(std::env::args().skip(1));
        if args.manifest_path.is_none() {
            args.manifest_path = std::env::var_os(MANIFEST_PATH_ENV).map(PathBuf::from);
        }
        args
    }

    pub(crate) fn parse_from_args(args: impl IntoIterator<Item = String>) -> Self {
        let mut args = args.into_iter().peekable();
        if args.peek().is_some_and(|arg| arg == "sniff-test") {
            args.next();
        }

        let mut parsed = Self::default();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--" => {
                    parsed.cargo_args.extend(args);
                    break;
                }
                "--manifest" => {
                    parsed.manifest_path =
                        Some(PathBuf::from(required_arg(&mut args, "--manifest")));
                }
                "--cache-dir" => {
                    parsed.cache_dir = Some(PathBuf::from(required_arg(&mut args, "--cache-dir")));
                }
                "--color" => {
                    let value = required_arg(&mut args, "--color");
                    parsed.color = value.parse::<ColorChoice>().unwrap_or_else(|error| {
                        eprintln!("sniff-test: invalid --color value: {error}");
                        std::process::exit(2);
                    });
                }
                "--message-format" => {
                    let value = required_arg(&mut args, "--message-format");
                    parsed.message_format =
                        value.parse::<MessageFormat>().unwrap_or_else(|error| {
                            eprintln!("sniff-test: {error}");
                            std::process::exit(2);
                        });
                }
                "--overflow-checks" => {
                    let value = required_arg(&mut args, "--overflow-checks");
                    parsed.overflow_checks =
                        Some(value.parse::<OverflowChecks>().unwrap_or_else(|error| {
                            eprintln!("sniff-test: invalid --overflow-checks value: {error}");
                            std::process::exit(2);
                        }));
                }
                "--build-std" => parsed.build_std = true,
                "--release" => parsed.release = true,
                other => {
                    eprintln!(
                        "sniff-test: unknown argument `{other}`; pass Cargo arguments after `--`"
                    );
                    std::process::exit(2);
                }
            }
        }

        parsed
    }

    pub(crate) fn parse_from_driver_args(
        args: impl IntoIterator<Item = String>,
    ) -> Result<Self, SniffTestArgParseError> {
        let mut args = args.into_iter();
        let mut parsed = Self::default();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--manifest" => {
                    parsed.manifest_path =
                        Some(PathBuf::from(required_driver_arg(&mut args, "--manifest")?));
                }
                "--cache-dir" => {
                    parsed.cache_dir = Some(PathBuf::from(required_driver_arg(
                        &mut args,
                        "--cache-dir",
                    )?));
                }
                "--color" => {
                    let value = required_driver_arg(&mut args, "--color")?;
                    parsed.color = value.parse::<ColorChoice>().map_err(|error| {
                        SniffTestArgParseError::new(format!("invalid --color value: {error}"))
                    })?;
                }
                "--message-format" => {
                    let value = required_driver_arg(&mut args, "--message-format")?;
                    parsed.message_format = value
                        .parse::<MessageFormat>()
                        .map_err(|error| SniffTestArgParseError::new(error.to_string()))?;
                }
                "--release" => return Err(frontend_only_driver_arg("--release")),
                "--build-std" => return Err(frontend_only_driver_arg("--build-std")),
                "--overflow-checks" => return Err(frontend_only_driver_arg("--overflow-checks")),
                "--" => {
                    return Err(SniffTestArgParseError::new(
                        "direct driver mode does not accept Cargo arguments after sniff-test arguments",
                    ));
                }
                other => {
                    return Err(SniffTestArgParseError::new(format!(
                        "unknown direct driver argument `{other}`; supported arguments are --manifest, --cache-dir, --color, and --message-format"
                    )));
                }
            }
        }

        Ok(parsed)
    }

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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

impl FromStr for ColorChoice {
    type Err = ColorChoiceParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "auto" => Ok(Self::Auto),
            "always" => Ok(Self::Always),
            "never" => Ok(Self::Never),
            other => Err(ColorChoiceParseError {
                value: other.to_owned(),
            }),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum MessageFormat {
    #[default]
    Human,
    Json,
}

impl FromStr for MessageFormat {
    type Err = MessageFormatParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "human" => Ok(Self::Human),
            "json" => Ok(Self::Json),
            other => Err(MessageFormatParseError {
                value: other.to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MessageFormatParseError {
    value: String,
}

impl fmt::Display for MessageFormatParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unsupported --message-format `{}`; expected human or json",
            self.value
        )
    }
}

impl std::error::Error for MessageFormatParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ColorChoiceParseError {
    value: String,
}

impl fmt::Display for ColorChoiceParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid color choice `{}`; expected auto, always, or never",
            self.value
        )
    }
}

impl std::error::Error for ColorChoiceParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SniffTestArgParseError {
    message: String,
}

impl SniffTestArgParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for SniffTestArgParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SniffTestArgParseError {}

fn required_arg(args: &mut impl Iterator<Item = String>, flag: &str) -> String {
    let Some(value) = args.next() else {
        eprintln!("sniff-test: {flag} requires a value");
        std::process::exit(2);
    };
    value
}

fn required_driver_arg(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, SniffTestArgParseError> {
    args.next().ok_or_else(|| {
        SniffTestArgParseError::new(format!("direct driver argument {flag} requires a value"))
    })
}

fn frontend_only_driver_arg(flag: &str) -> SniffTestArgParseError {
    let hint = match flag {
        "--release" => {
            "use `cargo sniff-test --release`, or pass release/profile rustc flags before the driver `--`"
        }
        "--build-std" => {
            "use `cargo sniff-test --build-std`; direct driver mode cannot rebuild std"
        }
        "--overflow-checks" => {
            "use `cargo sniff-test --overflow-checks`, or pass `-C overflow-checks=on/off` before the driver `--`"
        }
        _ => "use `cargo sniff-test` for Cargo frontend options",
    };
    SniffTestArgParseError::new(format!(
        "{flag} is a cargo-sniff-test frontend option, not a direct driver option; {hint}"
    ))
}
