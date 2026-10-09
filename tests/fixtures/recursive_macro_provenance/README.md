The tuple parser implementation reduces winnow's mutually recursive
`alt_trait_inner!` / `succ!` expansion. Distinct recursive expansions share source
locations but have different hygiene contexts. Extracting this crate must not
give one macro invocation inconsistent ancestry depending on which MIR operation
first exposes it.

Directly recursive macros ending in a runtime call and a raw-pointer dereference
check that adjacent frames are retained even when both their macro definition
and their source location are identical. The regression inspects persisted call
and effect facts, covering both macro-provenance extraction paths.
