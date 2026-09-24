//! Presentation of structured effect findings as rustc diagnostics and JSON.
#![feature(rustc_private)]
#![deny(warnings)]
#![warn(clippy::pedantic)]

extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_metadata;
extern crate rustc_middle;
extern crate rustc_span;

pub mod diagnostics;
pub mod findings;
pub mod interpretation;
pub mod output;
pub mod report;
