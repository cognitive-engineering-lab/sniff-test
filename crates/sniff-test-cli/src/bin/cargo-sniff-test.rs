#![feature(rustc_private)]

use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Command;

use sniff_test::config::{DEFAULT_MANIFEST_FILE, EXAMPLE_MANIFEST};

fn main() {
    if std::env::args_os()
        .nth(1)
        .as_deref()
        .map(std::path::Path::new)
        .and_then(std::path::Path::file_stem)
        == Some(OsStr::new("rustc"))
    {
        passthrough_rustc_version_probe();
        rustc_plugin::driver_main(sniff_test_cli::SniffTestPlugin);
        return;
    }

    if let Some(init_args) = InitArgs::from_env() {
        return init_args.run();
    }

    rustc_plugin::cli_main(sniff_test_cli::SniffTestPlugin);
}

struct InitArgs {
    path: PathBuf,
    force: bool,
}

impl InitArgs {
    fn from_env() -> Option<Self> {
        let mut args = std::env::args().skip(1).collect::<Vec<_>>();
        if args.first().is_some_and(|arg| arg == "sniff-test") {
            args.remove(0);
        }

        let command = args.first()?;
        if command != "init" {
            return None;
        }

        Some(Self::parse(args.into_iter().skip(1)))
    }

    fn parse(args: impl IntoIterator<Item = String>) -> Self {
        let mut path = PathBuf::from(DEFAULT_MANIFEST_FILE);
        let mut force = false;
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--force" => force = true,
                "--manifest" => {
                    let Some(value) = args.next() else {
                        eprintln!("sniff-test: {arg} requires a path");
                        std::process::exit(2);
                    };
                    path = PathBuf::from(value);
                }
                other => {
                    eprintln!("sniff-test: unknown init argument `{other}`");
                    std::process::exit(2);
                }
            }
        }

        Self { path, force }
    }

    fn run(&self) {
        if self.path.exists() && !self.force {
            eprintln!(
                "sniff-test: {} already exists; pass --force to overwrite it",
                self.path.display()
            );
            std::process::exit(1);
        }

        if let Err(error) = std::fs::write(&self.path, EXAMPLE_MANIFEST) {
            eprintln!(
                "sniff-test: failed to write {}: {error}",
                self.path.display()
            );
            std::process::exit(1);
        }

        println!("sniff-test: wrote {}", self.path.display());
    }
}

// to be fixed in https://github.com/cognitive-engineering-lab/rustc_plugin/pull/45
fn passthrough_rustc_version_probe() {
    let mut args = std::env::args_os();
    let _driver = args.next();
    let Some(rustc) = args.next() else {
        return;
    };
    let rustc_args = args.collect::<Vec<_>>();
    let mut saw_version = false;
    for arg in &rustc_args {
        match arg.as_os_str() {
            arg if arg == OsStr::new("--version")
                || arg == OsStr::new("-V")
                || arg == OsStr::new("-vV")
                || arg == OsStr::new("-Vv") =>
            {
                saw_version = true;
            }
            arg if arg == OsStr::new("--verbose") || arg == OsStr::new("-v") => {}
            _ => return,
        }
    }
    if !saw_version {
        return;
    }

    let status = Command::new(rustc)
        .args(rustc_args)
        .status()
        .unwrap_or_else(|error| {
            eprintln!("sniff-test: failed to run rustc version probe: {error}");
            std::process::exit(1);
        });

    std::process::exit(status.code().unwrap_or(1));
}
