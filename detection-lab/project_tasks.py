#!/usr/bin/env python3
"""Provide clean, provision, build and test tasks for Stage 8 B2."""

import argparse
import hashlib
import json
import py_compile
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
MINIMUM_PYTHON = (3, 11)

REQUIRED_SOURCE_FILES = [
    "detection-lab/detection_engine.py",
    "detection-lab/event_adapter.py",
    "detection-lab/fixture_validator.py",
    "detection-lab/project_tasks.py",
    "detection-lab/replay_detector.py",
    "detection-lab/replay_evaluator.py",
    "detection-lab/replay_validator.py",
    "detection-lab/run_full_replay.py",
    "detection-lab/run_regression.py",
    "fixtures/benign-holdouts.json",
    "fixtures/classification-diagnostics.json",
    "fixtures/mutation-tests.json",
    "fixtures/public-fixtures-malformed.json",
    "fixtures/public-fixtures.json",
    "fixtures/replay-malformed.jsonl",
    "fixtures/replay-smoke.jsonl",
    "rules/behavior-policy.json",
    "rules/replay-policy.json",
]

GENERATED_FILES = [
    "regression-results.xml",
    "raw-events/normalized-candidates.jsonl",
    "raw-events/source-accounting.json",
    "alerts/replay-alerts.jsonl",
    "alerts/replay-decisions.jsonl",
    "alerts/replay-summary.json",
]

GENERATED_DIRECTORIES = [
    "tests/results/full-run-one",
    "tests/results/full-run-two",
    "tests/results/clean-run",
]

GENERATED_SUMMARIES = [
    "tests/results/full-run-one-summary.json",
    "tests/results/full-run-two-summary.json",
    "tests/results/clean-run-summary.json",
]


def parse_arguments() -> argparse.Namespace:
    """Read the requested project task."""
    parser = argparse.ArgumentParser(
        description="Run a Stage 8 B2 project task."
    )
    parser.add_argument(
        "task",
        choices=["provision", "build", "test", "clean"],
        help="Project task to execute.",
    )
    parser.add_argument(
        "--replay",
        help=(
            "Assigned Windows replay path. Required for the "
            "complete scored test; omit for the public suite only."
        ),
    )
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    """Calculate a file SHA-256."""
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def source_path(relative_path: str) -> Path:
    """Resolve a repository-relative source path."""
    return ROOT / relative_path


def run_command(arguments: list[str]) -> int:
    """Run a child command with visible output."""
    completed = subprocess.run(
        arguments,
        cwd=ROOT,
        check=False,
    )
    return completed.returncode


def provision() -> int:
    """Verify Python and every required source input."""
    problems = []

    if sys.version_info[:2] < MINIMUM_PYTHON:
        problems.append(
            "Python 3.11 or newer is required."
        )

    missing = [
        relative_path
        for relative_path in REQUIRED_SOURCE_FILES
        if not source_path(relative_path).is_file()
    ]

    for relative_path in missing:
        problems.append(f"missing: {relative_path}")

    result = {
        "schema_version": "1.0",
        "python": {
            "major": sys.version_info.major,
            "minor": sys.version_info.minor,
            "micro": sys.version_info.micro,
        },
        "required_input_count": len(REQUIRED_SOURCE_FILES),
        "missing": missing,
        "problems": problems,
        "verdict": "pass" if not problems else "fail",
    }

    output = ROOT / "tests" / "results" / "provision.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(
        f"provision python={sys.version_info.major}."
        f"{sys.version_info.minor} "
        f"required_inputs={len(REQUIRED_SOURCE_FILES)} "
        f"verdict={result['verdict']}"
    )

    return 0 if not problems else 1


def build() -> int:
    """Compile every Python program and validate JSON inputs."""
    python_programs = sorted(
        path
        for path in (ROOT / "detection-lab").glob("*.py")
        if path.is_file()
    )

    json_inputs = sorted(
        list((ROOT / "fixtures").glob("*.json"))
        + list((ROOT / "rules").glob("*.json"))
    )

    problems = []
    source_hashes = {}

    for path in python_programs:
        relative = path.relative_to(ROOT).as_posix()

        try:
            py_compile.compile(
                str(path),
                doraise=True,
            )
            source_hashes[relative] = sha256_file(path)
        except py_compile.PyCompileError as error:
            problems.append(f"{relative}: {error}")

    for path in json_inputs:
        relative = path.relative_to(ROOT).as_posix()

        try:
            json.loads(path.read_text(encoding="utf-8"))
            source_hashes[relative] = sha256_file(path)
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as error:
            problems.append(f"{relative}: {error}")

    report = {
        "schema_version": "1.0",
        "python": {
            "major": sys.version_info.major,
            "minor": sys.version_info.minor,
            "micro": sys.version_info.micro,
        },
        "counts": {
            "python_programs": len(python_programs),
            "json_inputs": len(json_inputs),
            "problems": len(problems),
        },
        "source_hashes": dict(sorted(source_hashes.items())),
        "problems": sorted(problems),
        "verdict": "pass" if not problems else "fail",
    }

    output = (
        ROOT / "tests" / "results" / "build-validation.json"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(
        f"build python_programs={len(python_programs)} "
        f"json_inputs={len(json_inputs)} "
        f"problems={len(problems)} "
        f"verdict={report['verdict']}"
    )

    return 0 if not problems else 1


def test(replay: str | None) -> int:
    """Run either the public suite or complete signed-replay suite."""
    if replay:
        replay_path = Path(replay).expanduser().resolve()

        if not replay_path.is_file():
            print(f"test replay_not_found={replay_path}")
            return 1

        return run_command(
            [
                PYTHON,
                "detection-lab/run_full_replay.py",
                "--replay",
                str(replay_path),
                "--output-dir",
                "tests/results/clean-run",
                "--summary",
                "tests/results/clean-run-summary.json",
            ]
        )

    print(
        "test mode=public-only "
        "note=use --replay for the complete scored workflow"
    )

    return run_command(
        [
            PYTHON,
            "detection-lab/run_regression.py",
        ]
    )


def clean() -> int:
    """Remove only documented generated outputs."""
    removed = []

    for relative_path in GENERATED_FILES + GENERATED_SUMMARIES:
        path = ROOT / relative_path

        if path.is_file():
            path.unlink()
            removed.append(relative_path)

    for relative_path in GENERATED_DIRECTORIES:
        path = ROOT / relative_path

        if path.is_dir():
            shutil.rmtree(path)
            removed.append(relative_path)

    cache_directories = sorted(
        (ROOT / "detection-lab").glob("__pycache__")
    )

    for path in cache_directories:
        if path.is_dir():
            shutil.rmtree(path)
            removed.append(
                path.relative_to(ROOT).as_posix()
            )

    result = {
        "schema_version": "1.0",
        "removed": sorted(removed),
        "removed_count": len(removed),
        "verdict": "pass",
    }

    output = ROOT / "tests" / "results" / "clean-result.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(f"clean removed={len(removed)} verdict=pass")
    return 0


def main() -> int:
    """Dispatch the requested task."""
    arguments = parse_arguments()

    if arguments.task == "provision":
        return provision()

    if arguments.task == "build":
        return build()

    if arguments.task == "test":
        return test(arguments.replay)

    return clean()


if __name__ == "__main__":
    raise SystemExit(main())
