#!/usr/bin/env python3
"""Smoke-test sniff-test CLI and rustc-style diagnostics."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "tests" / "fixtures"


@dataclass(frozen=True)
class SmokeCase:
    name: str
    fixture: str
    expected_exit: int
    contains: tuple[str, ...]
    absent: tuple[str, ...] = ()
    crate_dir: str = "."
    working_dir: str | None = None
    config_append: str = ""
    args: tuple[str, ...] = ()
    stdout_empty: bool = True


CASES = (
    SmokeCase(
        name="compact-stack-hint",
        fixture="safe_markers",
        expected_exit=1,
        contains=(
            "error: function `safe_markers::unsafe_call` has an undocumented panic path",
            "note: panic may happen here: panic sink `core::panicking::panic`",
            "= note: reachable from `safe_markers::unsafe_call` to `core::panicking::panic`",
            "= note: set `show-full-stack-trace = true` under `[panics]` in sniff-test.toml",
            "error: function `safe_markers::unsafe_ratio` has an undocumented panic path",
            "compiler assertion: attempt to divide `total` (_1, argument 1) by zero",
        ),
        absent=(
            "reachable step 0:",
            "sniff-test[",
        ),
    ),
    SmokeCase(
        name="full-stack-trace",
        fixture="safe_markers",
        expected_exit=1,
        config_append="\nshow-full-stack-trace = true\n",
        contains=(
            "note: reachable step 0: safe_markers::unsafe_call --direct-call-> safe_markers::helper",
            "note: reachable step 1: safe_markers::helper --direct-call-> core::panicking::panic",
            "note: reachable step 0: safe_markers::unsafe_ratio --assert-> compiler assert attempt to divide `total` (_1, argument 1) by zero",
        ),
        absent=(
            "set `show-full-stack-trace = true`",
            "sniff-test[",
        ),
    ),
    SmokeCase(
        name="dependency-warning-footer",
        fixture="dependency_obligation",
        crate_dir="app",
        expected_exit=0,
        contains=(
            "warning: function `dependency_app::call_dependency` reaches a documented panic contract",
            "note: `dependency_obligation::documented` documents `# Panics` here",
            "warning: `dependency-app` (lib) generated 1 warning",
            "Finished `release` profile [optimized]",
        ),
        absent=(
            "error: could not compile",
            "sniff-test[",
        ),
    ),
    SmokeCase(
        name="direct-compiler-asserts",
        fixture="panic_axioms",
        expected_exit=1,
        contains=(
            "compiler assertion: attempt to divide `total_size` (_1, argument 1) by zero",
            "compiler assertion: attempt to calculate the remainder of `total_size` (_1, argument 1) with a zero divisor",
            "compiler assertion: index out of bounds",
            "error: could not compile `panic-axioms` (lib) due to 3 previous errors",
        ),
        absent=(
            "reachable from `panic_axioms::",
            "reachable step 0:",
            "sniff-test[",
        ),
    ),
    SmokeCase(
        name="cargo-manifest-path-forwarding",
        fixture="panic_axioms",
        working_dir="..",
        expected_exit=1,
        args=("--", "--manifest-path", "{fixture}/Cargo.toml"),
        contains=(
            "Checking panic-axioms",
            "error: function `panic_axioms::division` has an undocumented panic path",
            "error: could not compile `panic-axioms` (lib) due to 3 previous errors",
        ),
        absent=(
            "failed to read Cargo metadata",
            "sniff-test[",
        ),
    ),
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.parse_args()

    binary = build_cargo_sniff_test()
    failures: list[str] = []

    for case in CASES:
        output = run_case(binary, case)
        failures.extend(check_case(case, output))

    if failures:
        print("\n\n".join(failures), file=sys.stderr)
        return 1

    print(f"cli smoke passed ({len(CASES)} cases)")
    return 0


def build_cargo_sniff_test() -> Path:
    run(["cargo", "build", "-q", "-p", "sniff-test", "--bins"], cwd=REPO)
    metadata = json.loads(
        run(["cargo", "metadata", "--format-version", "1", "--no-deps"], cwd=REPO).stdout
    )
    binary = Path(metadata["target_directory"]) / "debug" / executable_name("cargo-sniff-test")
    if not binary.exists():
        raise RuntimeError(f"missing built cargo-sniff-test binary at {binary}")
    return binary


def executable_name(name: str) -> str:
    return f"{name}.exe" if os.name == "nt" else name


def run_case(binary: Path, case: SmokeCase) -> subprocess.CompletedProcess[str]:
    fixture = FIXTURES / case.fixture
    if not fixture.exists():
        raise RuntimeError(f"{case.name}: missing fixture {fixture}")

    with tempfile.TemporaryDirectory(prefix=f"sniff-test-cli-{case.name}-") as temp:
        root = Path(temp) / case.fixture
        shutil.copytree(fixture, root)
        if case.config_append:
            config = root / case.crate_dir / "sniff-test.toml"
            config.write_text(config.read_text() + case.config_append)

        working_dir = root / (case.working_dir or case.crate_dir)
        command = [
            str(binary),
            "--color",
            "never",
            "--release",
            *expand_args(case.args, root),
        ]
        return subprocess.run(command, cwd=working_dir, text=True, capture_output=True)


def expand_args(args: tuple[str, ...], fixture_root: Path) -> list[str]:
    return [arg.replace("{fixture}", fixture_root.name) for arg in args]


def check_case(case: SmokeCase, output: subprocess.CompletedProcess[str]) -> list[str]:
    failures = []
    if output.returncode != case.expected_exit:
        failures.append(
            f"{case.name}: exited {output.returncode}, expected {case.expected_exit}\n"
            f"stdout:\n{output.stdout}\n"
            f"stderr:\n{output.stderr}"
        )

    if case.stdout_empty and output.stdout:
        failures.append(f"{case.name}: expected empty stdout, got:\n{output.stdout}")

    for expected in case.contains:
        if expected not in output.stderr:
            failures.append(f"{case.name}: missing stderr fragment:\n{expected}\n\nstderr:\n{output.stderr}")

    for unexpected in case.absent:
        if unexpected in output.stderr:
            failures.append(
                f"{case.name}: unexpected stderr fragment:\n{unexpected}\n\nstderr:\n{output.stderr}"
            )

    return failures


def run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    output = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if output.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(command)}\n"
            f"stdout:\n{output.stdout}\n"
            f"stderr:\n{output.stderr}"
        )
    return output


if __name__ == "__main__":
    raise SystemExit(main())
