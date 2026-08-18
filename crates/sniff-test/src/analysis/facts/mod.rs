//! Typed, open-ended fact and provenance infrastructure.
//!
//! Analysis packs use the typed modules in this tree. JSON erasure is confined
//! to [`encoded`], the persistence boundary for independently versioned rows.

pub(crate) mod builder;
pub(crate) mod collection;
pub(crate) mod composition;
pub(crate) mod encoded;
pub(crate) mod evaluation;
pub(crate) mod evidence;
pub(crate) mod human;
pub(crate) mod pack;
pub(crate) mod panic;
pub(crate) mod pass;
pub(crate) mod program;
pub(crate) mod registry;
pub(crate) mod relations;
pub(crate) mod render;
pub(crate) mod safety;
pub(crate) mod schema;
pub(crate) mod view;
pub(crate) mod workspace;
