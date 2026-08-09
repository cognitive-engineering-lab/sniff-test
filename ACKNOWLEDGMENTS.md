# Acknowledgments

## Reachability analysis

The methodology behind sniff-test's reachability analysis was informed by
[Ferrocene](https://github.com/ferrocene/ferrocene), a downstream of the Rust
compiler maintained by Ferrous Systems. In particular, Ferrocene's use of
compiler queries and worklist traversal helped inform how sniff-test discovers
transitively reachable definitions.

The standalone `reachability` crate uses concrete function instances, a shared
graph index, per-root snapshots, typed edges, and configurable descent policy.

sniff-test is an independent project and is not a component of, or affiliated
with, Ferrocene or Ferrous Systems.
