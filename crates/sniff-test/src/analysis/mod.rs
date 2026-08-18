pub(crate) mod cache;
pub(crate) mod collected;
pub(crate) mod extract;
#[allow(
    dead_code,
    reason = "the compile-time pack API intentionally exposes extension points not used by every installed pack"
)]
pub(crate) mod facts;
pub(crate) mod graph;
pub(crate) mod interpret;
pub(crate) mod ir;
pub(crate) mod source;
pub(crate) mod workspace_closure;
