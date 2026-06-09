//! Arg parsing for the cargo frontend cli
use std::fmt;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sniff_test::cache::default_cache_dir;
use sniff_test::config::{DEFAULT_MANIFEST_FILE, OverflowChecks};

pub(crate) const MANIFEST_PATH_ENV: &str = "SNIFF_TEST_MANIFEST";

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SniffTestArgs {
    pub(crate) manifest_path: Option<PathBuf>,
    pub(crate) cache_dir: Option<PathBuf>,
    pub(crate) color: ColorChoice,
    pub(crate) overflow_checks: Option<OverflowChecks>,
    pub(crate) build_std: bool,
    pub(crate) release: bool,
    pub(crate) cargo_args: Vec<String>,
}

impl SniffTestArgs {
    pub(crate) fn parse_from_env() -> Self {
        let mut args = Self::parse_from_args(std::env::args().skip(1));
        if args.manifest_path.is_none() {
            args.manifest_path = std::env::var_os(MANIFEST_PATH_ENV).map(PathBuf::from);
        }
        args
    }

    fn parse_from_args(args: impl IntoIterator<Item = String>) -> Self {
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

fn required_arg(args: &mut impl Iterator<Item = String>, flag: &str) -> String {
    let Some(value) = args.next() else {
        eprintln!("sniff-test: {flag} requires a value");
        std::process::exit(2);
    };
    value
}

pub(crate) fn colors_enabled(choice: ColorChoice, rustc_color: Option<ColorChoice>) -> bool {
    match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => match rustc_color.unwrap_or(ColorChoice::Auto) {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => {
                std::env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal()
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use sniff_test::config::OverflowChecks;

    use super::{ColorChoice, SniffTestArgs};

    #[test]
    fn parser_strips_cargo_subcommand_name() {
        let args = SniffTestArgs::parse_from_args(
            [
                "sniff-test",
                "--manifest",
                "sniff-test.toml",
                "--cache-dir",
                "target/sniff-test",
                "--color",
                "always",
                "--overflow-checks",
                "on",
                "--",
                "--features",
                "demo",
            ]
            .into_iter()
            .map(String::from),
        );

        assert_eq!(args.manifest_path, Some(PathBuf::from("sniff-test.toml")));
        assert_eq!(args.cache_dir, Some(PathBuf::from("target/sniff-test")));
        assert_eq!(args.color, ColorChoice::Always);
        assert_eq!(args.overflow_checks, Some(OverflowChecks::On));
        assert_eq!(args.cargo_args, ["--features", "demo"]);
    }
}
