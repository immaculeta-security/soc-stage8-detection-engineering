#!/usr/bin/env python3
"""Run full replay normalization and the complete B2 regression suite."""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
RUNNER_VERSION = "1.0.0"


def parse_arguments() -> argparse.Namespace:
    """Read command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Run the complete Stage 8 B2 replay workflow."
    )
    parser.add_argument(
        "--replay",
        required=True,
        help="Path to the immutable signed Windows replay.",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory for deterministic derived outputs.",
    )
    parser.add_argument(
        "--summary",
        required=True,
        help="Path for the full-run machine-readable summary.",
    )
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    """Calculate a file SHA-256."""
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def run_command(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    """Run one project command from the repository root."""
    return subprocess.run(
        arguments,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def main() -> int:
    """Run adapter, regression and deterministic result accounting."""
    arguments = parse_arguments()

    replay_path = Path(arguments.replay).resolve()
    output_directory = Path(arguments.output_dir)
    summary_path = Path(arguments.summary)

    output_directory.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    candidates_path = (
        output_directory / "normalized-candidates.jsonl"
    )
    accounting_path = (
        output_directory / "source-accounting.json"
    )
    regression_copy = (
        output_directory / "regression-results.xml"
    )

    adapter = run_command(
        [
            PYTHON,
            "detection-lab/event_adapter.py",
            "--input",
            str(replay_path),
            "--candidates-output",
            str(candidates_path),
            "--accounting-output",
            str(accounting_path),
        ]
    )

    regression = run_command(
        [
            PYTHON,
            "detection-lab/run_regression.py",
        ]
    )

    root_regression = ROOT / "regression-results.xml"

    problems = []

    if adapter.returncode != 0:
        problems.append(
            f"adapter_exit={adapter.returncode}"
        )

    if regression.returncode != 0:
        problems.append(
            f"regression_exit={regression.returncode}"
        )

    required_outputs = [
        candidates_path,
        accounting_path,
        root_regression,
    ]

    for path in required_outputs:
        if not path.is_file():
            problems.append(f"missing_output={path.name}")

    if root_regression.is_file():
        shutil.copyfile(
            root_regression,
            regression_copy,
        )

    output_hashes = {}

    for path in (
        candidates_path,
        accounting_path,
        regression_copy,
    ):
        if path.is_file():
            output_hashes[path.name] = sha256_file(path)

    source_accounting = {}

    if accounting_path.is_file():
        source_accounting = json.loads(
            accounting_path.read_text(encoding="utf-8")
        )

    summary = {
        "schema_version": "1.0",
        "runner_version": RUNNER_VERSION,
        "input": {
            "file_name": replay_path.name,
            "bytes": (
                replay_path.stat().st_size
                if replay_path.is_file()
                else None
            ),
            "sha256": (
                sha256_file(replay_path)
                if replay_path.is_file()
                else None
            ),
        },
        "commands": {
            "adapter_exit": adapter.returncode,
            "adapter_stdout": adapter.stdout.strip(),
            "adapter_stderr": adapter.stderr.strip(),
            "regression_exit": regression.returncode,
            "regression_stdout": regression.stdout.strip(),
            "regression_stderr": regression.stderr.strip(),
        },
        "source_counts": source_accounting.get(
            "counts",
            {},
        ),
        "output_hashes": dict(sorted(output_hashes.items())),
        "problems": sorted(problems),
        "verdict": "pass" if not problems else "fail",
    }

    summary_path.write_text(
        json.dumps(
            summary,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        f"full-run verdict={summary['verdict']} "
        f"adapter_exit={adapter.returncode} "
        f"regression_exit={regression.returncode} "
        f"summary={summary_path}"
    )

    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
