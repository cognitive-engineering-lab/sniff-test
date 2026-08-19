pub(crate) mod cache;
pub(crate) mod collected;
pub(crate) mod extract;
pub(crate) mod findings;
// The typed-fact framework intentionally exposes symmetric construction, query,
// rendering, and validation APIs. Production packs use only a subset of that
// internal extension surface, while the complete contracts are exercised by the
// framework and pack test suites.
#[allow(dead_code, reason = "internal typed-fact extension surface")]
pub(crate) mod facts;
pub(crate) mod graph;
#[cfg(test)]
pub(crate) mod interpret;
pub(crate) mod ir;
pub(crate) mod source;
pub(crate) mod workspace_closure;
