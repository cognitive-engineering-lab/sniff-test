fmt:
    cargo fmt --check

unit:
    cargo test -q --workspace

fixtures:
    cargo insta test --check --unreferenced ignore -p sniff-test --test fixtures

fixtures-review:
    cargo insta test --review -p sniff-test --test fixtures

fixtures-accept:
    cargo insta test --accept -p sniff-test --test fixtures

fixture case:
    cargo insta test --check --unreferenced ignore -p sniff-test --test fixtures -- {{case}}

cli:
    cargo insta test --check --unreferenced ignore -p sniff-test --test cli

cli-review:
    cargo insta test --review -p sniff-test --test cli

cli-accept:
    cargo insta test --accept -p sniff-test --test cli

cli-case case:
    cargo insta test --check --unreferenced ignore -p sniff-test --test cli -- {{case}}

snapshots:
    cargo insta test --check --unreferenced reject -p sniff-test

clippy:
    cargo clippy -q --workspace --all-targets -- -D warnings -D clippy::pedantic

check: fmt unit snapshots clippy
