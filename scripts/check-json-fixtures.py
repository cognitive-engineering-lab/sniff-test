#!/usr/bin/env python3
"""Check sniff-test JSON fixture output."""

from __future__ import annotations

import argparse
import difflib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    print("python 3.11+ is required for tomllib", file=sys.stderr)
    raise


REPO = Path(__file__).resolve().parents[1]
CASES_PATH = REPO / "tests" / "cases.toml"
FIXTURES = REPO / "tests" / "fixtures"
EXPECTED = REPO / "tests" / "expected"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--bless",
        action="store_true",
        help="update expected JSON outputs instead of comparing",
    )
    parser.add_argument(
        "cases",
        nargs="*",
        help="case names to run; defaults to all cases",
    )
    args = parser.parse_args()

    binary = build_cargo_sniff_test()
    sysroot = rustc_sysroot()
    cases = select_cases(load_cases(), args.cases)
    failures = []

    for case in cases:
        actual = run_case(binary, sysroot, case)
        expected_path = EXPECTED / f"{case['name']}.json"
        serialized = json.dumps(actual, indent=2, sort_keys=True) + "\n"

        if args.bless:
            EXPECTED.mkdir(parents=True, exist_ok=True)
            expected_path.write_text(serialized)
            print(f"updated {expected_path.relative_to(REPO)}")
            continue

        if not expected_path.exists():
            failures.append(f"{case['name']}: missing {expected_path.relative_to(REPO)}")
            continue

        expected = expected_path.read_text()
        if serialized != expected:
            diff = "".join(
                difflib.unified_diff(
                    expected.splitlines(keepends=True),
                    serialized.splitlines(keepends=True),
                    fromfile=str(expected_path.relative_to(REPO)),
                    tofile=f"{case['name']} actual",
                )
            )
            failures.append(diff)

    if failures:
        print("\n\n".join(failures), file=sys.stderr)
        return 1

    print(f"json fixtures passed ({len(cases)} cases)")
    return 0


def build_cargo_sniff_test() -> Path:
    run(["cargo", "build", "-q", "-p", "sniff-test", "--bins"], cwd=REPO)
    metadata = json.loads(run(["cargo", "metadata", "--format-version", "1", "--no-deps"], cwd=REPO).stdout)
    binary = Path(metadata["target_directory"]) / "debug" / executable_name("cargo-sniff-test")
    if not binary.exists():
        raise RuntimeError(f"missing built cargo-sniff-test binary at {binary}")
    return binary


def executable_name(name: str) -> str:
    return f"{name}.exe" if os.name == "nt" else name


def rustc_sysroot() -> str:
    rustc = os.environ.get("RUSTC", "rustc")
    output = run([rustc, "--print", "sysroot"], cwd=REPO)
    return output.stdout.strip()


def load_cases() -> list[dict]:
    data = tomllib.loads(CASES_PATH.read_text())
    return data["case"]


def select_cases(cases: list[dict], names: list[str]) -> list[dict]:
    if not names:
        return cases

    by_name = {case["name"]: case for case in cases}
    unknown = sorted(set(names) - set(by_name))
    if unknown:
        raise RuntimeError(f"unknown case(s): {', '.join(unknown)}")
    return [by_name[name] for name in names]


def run_case(binary: Path, sysroot: str, case: dict) -> list[dict]:
    fixture = FIXTURES / case["fixture"]
    if not fixture.exists():
        raise RuntimeError(f"{case['name']}: missing fixture {fixture}")

    with tempfile.TemporaryDirectory(prefix=f"sniff-test-{case['name']}-") as temp:
        root = Path(temp) / case["fixture"]
        shutil.copytree(fixture, root)
        crate_dir = root / case.get("crate_dir", ".")
        command = [
            str(binary),
            "--message-format",
            "json",
            "--color",
            "never",
            "--release",
            *case.get("args", []),
        ]
        output = subprocess.run(command, cwd=crate_dir, text=True, capture_output=True)
        expected_exit = case.get("exit_code", 0)
        if output.returncode != expected_exit:
            raise RuntimeError(
                f"{case['name']}: cargo-sniff-test exited {output.returncode}, expected {expected_exit}\n"
                f"stdout:\n{output.stdout}\n"
                f"stderr:\n{output.stderr}"
            )

        messages = [
            normalize_json(json.loads(line), root, sysroot)
            for line in output.stdout.splitlines()
            if line.strip()
        ]
        if not messages:
            raise RuntimeError(f"{case['name']}: no JSON messages emitted")

    messages.sort(key=message_sort_key)
    return messages


def normalize_json(value, fixture_root: Path, sysroot: str):
    if isinstance(value, dict):
        for key in list(value):
            if key in {
                "artifact-id",
                "artifact-path",
                "exact-cache-path",
                "rustc-version",
                "metadata",
                "extra-filename",
            }:
                value[key] = f"[{key.upper().replace('-', '_')}]"
            else:
                value[key] = normalize_json(value[key], fixture_root, sysroot)
        return value

    if isinstance(value, list):
        return [normalize_json(item, fixture_root, sysroot) for item in value]

    if isinstance(value, str):
        return value.replace(str(fixture_root), "[FIXTURE]").replace(sysroot, "[SYSROOT]")

    return value


def message_sort_key(message: dict) -> tuple[str, str, str]:
    artifact = message.get("artifact", {})
    return (
        message.get("reason", ""),
        artifact.get("crate-name", ""),
        message.get("scope", ""),
    )


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
