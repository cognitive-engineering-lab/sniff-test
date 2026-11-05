This fixture injects markers through `[overrides.crates."crate"."version"]`
without modifying Rust source or cached dependency facts. Keep selector line
numbers in sync with the corresponding source statements.

- Default: selected local division, named contract call, and dependency panic
  are justified; adjacent control sites remain reportable. The named call also
  checks that injecting a marker leaves the callee's contract intact.
- `partial.toml`: exact matching still reports the missing `bounded` requirement.
- `source-callsite.toml`: the same injections work with source-callsite probing.
- `--effect safety`: unused panic markers do not enable or require panic facts.
- `ambiguous.toml`: one injected block spanning two independent divisions still
  produces a marker-ambiguity finding.

The related `source_justification_binary` fixture keeps a marker in an unselected
binary function. CLI coverage toggles the override file against the same cached
dependency and checks that injections are reapplied without persisting markers.
Another CLI regression compiles the dependency source as a local module too,
verifies both crates share a source ID, and checks crate and version isolation.
