# Source-located contract overrides

The selectors in this fixture identify a Rust crate, an exact Cargo package
version, and a package-relative source path with an inclusive range of definition
start lines. Keep the selectors in sync when moving the selected definitions.

| Configuration | Expected behavior |
| --- | --- |
| `sniff-test.toml` | The selected local function and dependency function receive panic contracts. A bodyless trait method also receives its contract. The adjacent function retains its concrete panic. The source selector replaces the conflicting namespace override. |
| `justified.toml` | Complete named `PANIC` justifications discharge local, dependency, and trait-method obligations. No findings remain. |
| `generic-effects.toml` | Source selectors supply safety, allocation, and file contracts. Each missing requirement is reported; the fully justified callers remain quiet. Run with `--effect safety --effect allocation --effect file`. |
| `inactive.toml` | Selectors for another version, an unloaded source path, or an unloaded crate remain inactive. The namespace fallback remains active. |

Run all four fixture cases from the repository root:

```sh
cargo test -p sniff-test --test fixtures source_contract_overrides
```

CLI regressions additionally reject a loaded source file whose selected
function no longer exists, and reject a marker-free dependency cache whose
source hash no longer matches the available file:

```sh
cargo test -p sniff-test --test cli source_override
```
