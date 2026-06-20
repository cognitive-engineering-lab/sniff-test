fmt:
    cargo fmt --check

unit:
    cargo test -q --workspace

json-fixtures:
    cargo test -q -p sniff-test --test json_fixtures

cli-smoke:
    python3 scripts/check-cli-smoke.py

clippy:
    cargo clippy -q --workspace --all-targets -- -D warnings -D clippy::pedantic

check: fmt unit json-fixtures cli-smoke clippy
