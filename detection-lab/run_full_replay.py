#!/usr/bin/env python3
"""Run the complete deterministic B2 replay and regression workflow."""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
RUNNER_VERSION = "2.0.0"


def parse_arguments() -> argparse.Namespace:
    """Read command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Run the complete Stage 8 B2 workflow."
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
        help="Path for the full-run summary JSON.",
    )
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    """Calculate a file SHA-256."""
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def run_command(arguments: list[str]) -> dict[str, Any]:
    """Run one project command and retain sanitized execution output."""
    completed = subprocess.run(
        arguments,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    return {
        "exit_code": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def main() -> int:
    """Run normalization, detection, evaluation and regression."""
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
    decisions_path = (
        output_directory / "replay-decisions.jsonl"
    )
    alerts_path = (
        output_directory / "replay-alerts.jsonl"
    )
    detection_summary_path = (
        output_directory / "replay-summary.json"
    )
    evaluation_path = (
        output_directory / "replay-evaluation.json"
    )
    regression_copy_path = (
        output_directory / "regression-results.xml"
    )

    commands = {}

    commands["adapter"] = run_command(
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

    commands["detector"] = run_command(
        [
            PYTHON,
            "detection-lab/replay_detector.py",
            "--input",
            str(candidates_path),
            "--policy",
            "rules/replay-policy.json",
            "--decisions-output",
            str(decisions_path),
            "--alerts-output",
            str(alerts_path),
            "--summary-output",
            str(detection_summary_path),
        ]
    )

    commands["evaluator"] = run_command(
        [
            PYTHON,
            "detection-lab/replay_evaluator.py",
            "--replay",
            str(replay_path),
            "--normalized",
            str(candidates_path),
            "--decisions",
            str(decisions_path),
            "--output",
            str(evaluation_path),
        ]
    )

    commands["regression"] = run_command(
        [
            PYTHON,
            "detection-lab/run_regression.py",
        ]
    )

    root_regression = ROOT / "regression-results.xml"

    if root_regression.is_file():
        shutil.copyfile(
            root_regression,
            regression_copy_path,
        )

    required_outputs = [
        candidates_path,
        accounting_path,
        decisions_path,
        alerts_path,
        detection_summary_path,
        evaluation_path,
        regression_copy_path,
    ]

    problems = []

    for command_name, command_result in commands.items():
        if command_result["exit_code"] != 0:
            problems.append(
                f"{command_name}_exit="
                f"{command_result['exit_code']}"
            )

    for path in required_outputs:
        if not path.is_file():
            problems.append(f"missing_output={path.name}")

    accounting = {}
    detection_summary = {}
    evaluation = {}

    if accounting_path.is_file():
        accounting = json.loads(
            accounting_path.read_text(encoding="utf-8")
        )

    if detection_summary_path.is_file():
        detection_summary = json.loads(
            detection_summary_path.read_text(encoding="utf-8")
        )

    if evaluation_path.is_file():
        evaluation = json.loads(
            evaluation_path.read_text(encoding="utf-8")
        )

    if accounting.get("verdict") != "pass":
        problems.append("source_accounting_not_pass")

    if detection_summary.get("verdict") != "pass":
        problems.append("replay_detection_not_pass")

    if evaluation.get("verdict") != "pass":
        problems.append("replay_evaluation_not_pass")

    output_hashes = {}

    for path in required_outputs:
        if path.is_file():
            output_hashes[path.name] = sha256_file(path)

    report = {
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
            name: {
                "exit_code": result["exit_code"],
                "stdout": result["stdout"],
                "stderr": result["stderr"],
            }
            for name, result in sorted(commands.items())
        },
        "source_counts": accounting.get("counts", {}),
        "detection_counts": detection_summary.get(
            "counts",
            {},
        ),
        "evaluation_counts": evaluation.get(
            "counts",
            {},
        ),
        "evaluation_status_counts": evaluation.get(
            "status_counts",
            {},
        ),
        "output_hashes": dict(sorted(output_hashes.items())),
        "problems": sorted(set(problems)),
        "verdict": "pass" if not problems else "fail",
    }

    summary_path.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        f"full-run verdict={report['verdict']} "
        f"adapter={commands['adapter']['exit_code']} "
        f"detector={commands['detector']['exit_code']} "
        f"evaluator={commands['evaluator']['exit_code']} "
        f"regression={commands['regression']['exit_code']} "
        f"summary={summary_path}"
    )

    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
