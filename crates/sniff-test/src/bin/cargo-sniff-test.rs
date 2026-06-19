#![feature(rustc_private)]

use std::path::PathBuf;
use std::process::ExitCode;

use sniff_test::config::{DEFAULT_MANIFEST_FILE, EXAMPLE_MANIFEST};

fn main() -> ExitCode {
    if help_requested() {
        print_help();
        return ExitCode::SUCCESS;
    }

    if let Some(init_args) = InitArgs::from_env() {
        return init_args.run();
    }

    sniff_test::cargo_frontend()
}

fn help_requested() -> bool {
    let mut args = std::env::args().skip(1).peekable();
    if args.peek().is_some_and(|arg| arg == "sniff-test") {
        args.next();
    }

    args.take_while(|arg| arg != "--")
        .any(|arg| arg == "--help" || arg == "-h")
}

fn print_help() {
    println!(
        "Run sniff-test panic reachability analysis through Cargo.\n\n\
Usage:\n    cargo sniff-test [OPTIONS] [-- CARGO-ARGS]\n    cargo-sniff-test [sniff-test] [OPTIONS] [-- CARGO-ARGS]\n\n\
Commands:\n    init                    Write a sample sniff-test.toml\n\n\
Options:\n    --manifest PATH         Path to sniff-test.toml\n    --cache-dir DIR         Analysis cache directory\n    --color auto|always|never\n    --message-format human|json\n    --overflow-checks on|off\n    --build-std\n    --release\n    -h, --help              Print this help\n    -V, --version           Print version information\n\n\
Cargo arguments after `--` are passed to `cargo check`."
    );
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

    fn run(&self) -> ExitCode {
        if self.path.exists() && !self.force {
            eprintln!(
                "sniff-test: {} already exists; pass --force to overwrite it",
                self.path.display()
            );
            return ExitCode::FAILURE;
        }

        if let Err(error) = std::fs::write(&self.path, EXAMPLE_MANIFEST) {
            eprintln!(
                "sniff-test: failed to write {}: {error}",
                self.path.display()
            );
            return ExitCode::FAILURE;
        }

        println!("sniff-test: wrote {}", self.path.display());
        ExitCode::SUCCESS
    }
}
