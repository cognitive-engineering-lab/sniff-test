fmt:
    cargo fmt --check

unit:
    cargo test -q --workspace

json-fixtures:
    python3 scripts/check-json-fixtures.py

cli-smoke:
    python3 scripts/check-cli-smoke.py

clippy:
    cargo clippy -q --workspace --all-targets -- -D warnings -D clippy::pedantic

check: fmt unit json-fixtures cli-smoke clippy
