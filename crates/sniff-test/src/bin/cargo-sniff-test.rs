#![feature(rustc_private)]

use std::process::ExitCode;

fn main() -> ExitCode {
    sniff_test::cargo_frontend()
}
