#!/usr/bin/env python3
"""Provide safe provision, build, test and clean project commands."""

import argparse
import hashlib
import json
import py_compile
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_DIRECTORIES = [
    "alerts",
    "decoders",
    "detection-lab",
    "fixtures",
    "raw-events",
    "rules",
    "tests",
    "tests/results",
]

REQUIRED_INPUTS = [
    "detection-lab/replay_validator.py",
    "detection-lab/fixture_validator.py",
    "detection-lab/detection_engine.py",
    "detection-lab/run_regression.py",
    "fixtures/public-fixtures.json",
    "fixtures/public-fixtures-malformed.json",
    "fixtures/replay-smoke.jsonl",
    "fixtures/replay-malformed.jsonl",
    "fixtures/mutation-tests.json",
    "rules/behavior-policy.json",
]

PYTHON_PROGRAMS = [
    "detection-lab/replay_validator.py",
    "detection-lab/fixture_validator.py",
    "detection-lab/detection_engine.py",
    "detection-lab/run_regression.py",
    "detection-lab/project_tasks.py",
]

JSON_INPUTS = [
    "fixtures/public-fixtures.json",
    "fixtures/public-fixtures-malformed.json",
    "fixtures/mutation-tests.json",
    "rules/behavior-policy.json",
]

GENERATED_OUTPUTS = [
    "regression-results.xml",
    "tests/results/build-validation.json",
    "tests/results/public-fixture-validation.json",
    "tests/results/public-fixture-malformed-validation.json",
    "tests/results/replay-smoke-validation.json",
    "tests/results/replay-malformed-validation.json",
    "tests/results/public-detection-results.json",
    "tests/results/mutation-results.json",
]


def sha256_file(path: Path) -> str:
    """Return the SHA-256 fingerprint of a file."""
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def project_path(relative_path: str) -> Path:
    """Return a resolved path that must remain inside the project."""
    path = (ROOT / relative_path).resolve()

    if path != ROOT and ROOT not in path.parents:
        raise ValueError(
            f"Refusing path outside project: {relative_path}"
        )

    return path


def provision() -> int:
    """Prepare local directories and verify required inputs."""
    if sys.version_info < (3, 10):
        print("Python 3.10 or newer is required.", file=sys.stderr)
        return 1

    for relative_directory in REQUIRED_DIRECTORIES:
        project_path(relative_directory).mkdir(
            parents=True,
            exist_ok=True,
        )

    missing = [
        relative_path
        for relative_path in REQUIRED_INPUTS
        if not project_path(relative_path).is_file()
    ]

    if missing:
        print("Missing required inputs:", file=sys.stderr)

        for relative_path in missing:
            print(f"- {relative_path}", file=sys.stderr)

        return 1

    print(
        "provision"
        f" python={sys.version_info.major}.{sys.version_info.minor}"
        f" required_inputs={len(REQUIRED_INPUTS)}"
        " verdict=pass"
    )

    return 0


def build() -> int:
    """Compile Python and validate JSON configuration inputs."""
    problems: list[str] = []

    for relative_path in PYTHON_PROGRAMS:
        path = project_path(relative_path)

        try:
            py_compile.compile(
                str(path),
                doraise=True,
            )
        except py_compile.PyCompileError as exc:
            problems.append(
                f"{relative_path}: {exc.msg}"
            )

    for relative_path in JSON_INPUTS:
        path = project_path(relative_path)

        try:
            with path.open("r", encoding="utf-8") as handle:
                json.load(handle)
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            problems.append(
                f"{relative_path}: {exc}"
            )

    source_hashes = {
        relative_path: sha256_file(project_path(relative_path))
        for relative_path in sorted(
            set(PYTHON_PROGRAMS + JSON_INPUTS)
        )
        if project_path(relative_path).is_file()
    }

    result: dict[str, Any] = {
        "schema_version": "1.0",
        "python": {
            "major": sys.version_info.major,
            "minor": sys.version_info.minor,
            "micro": sys.version_info.micro,
        },
        "counts": {
            "python_programs": len(PYTHON_PROGRAMS),
            "json_inputs": len(JSON_INPUTS),
            "problems": len(problems),
        },
        "problems": problems,
        "source_hashes": source_hashes,
        "verdict": "pass" if not problems else "fail",
    }

    output_path = project_path(
        "tests/results/build-validation.json"
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        "build"
        f" python_programs={len(PYTHON_PROGRAMS)}"
        f" json_inputs={len(JSON_INPUTS)}"
        f" problems={len(problems)}"
        f" verdict={result['verdict']}"
    )

    return 0 if not problems else 1


def test() -> int:
    """Run the unattended regression suite."""
    command = [
        sys.executable,
        str(project_path(
            "detection-lab/run_regression.py"
        )),
    ]

    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
    )

    return completed.returncode


def clean() -> int:
    """Remove only the allowlisted generated outputs."""
    removed = 0

    for relative_path in GENERATED_OUTPUTS:
        path = project_path(relative_path)

        if path.is_file():
            path.unlink()
            removed += 1

    print(
        f"clean removed={removed} verdict=pass"
    )

    return 0


def parse_args() -> argparse.Namespace:
    """Read the requested project task."""
    parser = argparse.ArgumentParser(
        description="Run a Stage 8 project task."
    )

    parser.add_argument(
        "task",
        choices=[
            "provision",
            "build",
            "test",
            "clean",
        ],
        help="Project task to execute.",
    )

    return parser.parse_args()


def main() -> int:
    """Dispatch one project task."""
    args = parse_args()

    tasks = {
        "provision": provision,
        "build": build,
        "test": test,
        "clean": clean,
    }

    return tasks[args.task]()


if __name__ == "__main__":
    raise SystemExit(main())
